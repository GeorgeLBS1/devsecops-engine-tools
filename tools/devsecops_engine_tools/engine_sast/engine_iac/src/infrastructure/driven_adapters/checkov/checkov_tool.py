import yaml
import subprocess
import os
import platform
import queue
import threading
import json
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions

from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_deserealizator import (
    CheckovDeserealizator,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_config import (
    CheckovConfig,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.helpers.commons import (
    search_folders,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
)

from devsecops_engine_utilities.github.infrastructure.github_api import GithubApi
from devsecops_engine_utilities.ssh.managment_private_key import (
    create_ssh_private_file,
    add_ssh_private_key,
    decode_base64,
    config_knowns_hosts,
)


class CheckovTool(ToolGateway):
    CHECKOV_CONFIG_FILE = "checkov_config.yaml"
    TOOL = "CHECKOV"

    def create_config_file(self, checkov_config: CheckovConfig):
        with open(
            checkov_config.path_config_file
            + checkov_config.config_file_name
            + self.CHECKOV_CONFIG_FILE,
            "w",
        ) as file:
            yaml.dump(checkov_config.dict_confg_file, file)
            file.close()

    def configurate_external_checks(self, config_tool: ConfigTool, secret_tool):
        agent_env = None
        try:
            if secret_tool is None:
                print("Secrets manager is not enabled to configure external checks")
            else:
                if (
                    config_tool.use_external_checks_git == "True"
                    and platform.system()
                    in (
                        "Linux",
                        "Darwin",
                    )
                ):
                    config_knowns_hosts(
                        config_tool.repository_ssh_host,
                        config_tool.repository_public_key_fp,
                    )
                    ssh_key_content = decode_base64(
                        secret_tool, "repository_ssh_private_key"
                    )
                    ssh_key_file_path = "/tmp/ssh_key_file"
                    create_ssh_private_file(ssh_key_file_path, ssh_key_content)
                    ssh_key_password = decode_base64(
                        secret_tool, "repository_ssh_password"
                    )
                    agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

                # Create configuration dir external checks
                if config_tool.use_external_checks_dir == "True":
                    github_api = GithubApi(secret_tool["github_token"])
                    github_api.download_latest_release_assets(
                        config_tool.external_dir_owner,
                        config_tool.external_dir_repository,
                        "/tmp",
                    )

        except Exception as ex:
            print(f"An error ocurred configuring external checks {ex}")
        return agent_env

    def execute(self, checkov_config: CheckovConfig):
        command = (
            "checkov --config-file "
            + checkov_config.path_config_file
            + checkov_config.config_file_name
            + self.CHECKOV_CONFIG_FILE
        )
        env_modified = dict(os.environ)
        if checkov_config.env is not None:
            env_modified = {**dict(os.environ), **checkov_config.env}
        result = subprocess.run(
            command, capture_output=True, text=True, shell=True, env=env_modified
        )
        output = result.stdout.strip()
        error = result.stderr.strip()
        if error is not None and error != "":
            print(f"Error running checkov.. {error}")
        return output

    def async_scan(self, queue, checkov_config: CheckovConfig):
        result = []
        output = self.execute(checkov_config)
        result.append(json.loads(output))
        queue.put(result)

    def complete_config_tool(self, data_file_tool, exclusions, pipeline, secret_tool):
        config_tool = ConfigTool(json_data=data_file_tool, tool=self.TOOL)

        config_tool.exclusions = exclusions
        config_tool.scope_pipeline = pipeline

        if config_tool.exclusions.get("All") is not None:
            config_tool.exclusions_all = config_tool.exclusions.get("All").get(
                self.TOOL
            )
        if config_tool.exclusions.get(config_tool.scope_pipeline) is not None:
            config_tool.exclusions_scope = config_tool.exclusions.get(
                config_tool.scope_pipeline
            ).get(self.TOOL)
        folders_to_scan = search_folders(
            config_tool.search_pattern, config_tool.ignore_search_pattern
        )

        # Create configuration external checks
        agent_env = self.configurate_external_checks(config_tool, secret_tool)

        return config_tool, folders_to_scan, agent_env

    def scan_folders(
        self, folders_to_scan, config_tool: ConfigTool, agent_env, environment
    ):
        output_queue = queue.Queue()
        # Crea una lista para almacenar los hilos
        threads = []
        for folder in folders_to_scan:
            for rule in config_tool.rules_data_type:
                checkov_config = CheckovConfig(
                    path_config_file="",
                    config_file_name=rule,
                    checks=[
                        key
                        for key, value in config_tool.rules_data_type[rule].items()
                        if value["environment"].get(environment)
                    ],
                    soft_fail=False,
                    directories=folder,
                    external_checks_git=[
                        f"{config_tool.external_checks_git}/kubernetes"
                    ]
                    if config_tool.use_external_checks_git == "True"
                    and agent_env is not None
                    and rule == "RULES_K8S"
                    else [],
                    env=agent_env,
                    external_checks_dir=f"/tmp/{config_tool.external_asset_name}"
                    if config_tool.use_external_checks_dir == "True"
                    and rule == "RULES_K8S"
                    else [],
                )

                checkov_config.create_config_dict()
                self.create_config_file(checkov_config)
                config_tool.rules_all.update(config_tool.rules_data_type[rule])
                t = threading.Thread(
                    target=self.async_scan,
                    args=(output_queue, checkov_config),
                )
                t.start()
                threads.append(t)
        # Espera a que todos los hilos terminen
        for t in threads:
            t.join()
        # Recopila las salidas de las tareas
        result_scans = []
        while not output_queue.empty():
            result = output_queue.get()
            result_scans.extend(result)
        return result_scans

    def run_tool(self, init_config_tool, exclusions, environment, pipeline, secret_tool):
        config_tool, folders_to_scan, agent_env = self.complete_config_tool(
            init_config_tool, exclusions, pipeline, secret_tool
        )

        result_scans = self.scan_folders(
            folders_to_scan, config_tool, agent_env, environment
        )

        checkov_deserealizator = CheckovDeserealizator()
        findings_list = checkov_deserealizator.get_list_finding(
            result_scans, config_tool.rules_all
        )

        totalized_exclusions = []
        totalized_exclusions.extend(
            map(lambda elem: Exclusions(**elem), config_tool.exclusions_all)
        ) if config_tool.exclusions_all is not None else None
        totalized_exclusions.extend(
            map(lambda elem: Exclusions(**elem), config_tool.exclusions_scope)
        ) if config_tool.exclusions_scope is not None else None

        input_core = InputCore(
            totalized_exclusions=totalized_exclusions,
            threshold_defined=config_tool.threshold,
            path_file_results=generate_file_from_tool(
                self.TOOL, result_scans, config_tool.rules_all
            ),
            custom_message_break_build=config_tool.message_info_sast_rm,
            scope_pipeline=config_tool.scope_pipeline,
        )
        return findings_list, input_core