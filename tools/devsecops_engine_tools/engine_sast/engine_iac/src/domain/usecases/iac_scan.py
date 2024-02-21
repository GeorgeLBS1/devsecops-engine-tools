import os
import re
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore
)
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class IacScan:
    def __init__(
        self, tool_gateway: ToolGateway, devops_platform_gateway: DevopsPlatformGateway
    ):
        self.tool_gateway = tool_gateway
        self.devops_platform_gateway = devops_platform_gateway

    def process(self, dict_args, secret_tool, tool):
        init_config_tool = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_sast/engine_iac/ConfigTool.json"
        )

        exclusions = self.devops_platform_gateway.get_remote_config(
            dict_args["remote_config_repo"], "engine_sast/engine_iac/Exclusions.json"
        )

        config_tool, folders_to_scan, skip_tool = self.complete_config_tool(
            init_config_tool, exclusions, tool, dict_args
        )


        findings_list, path_file_results = [], None
        if skip_tool == "false":
            findings_list, path_file_results = self.tool_gateway.run_tool(
                config_tool,
                folders_to_scan,
                dict_args["environment"],
                dict_args["platform"],
                secret_tool,
            )

        totalized_exclusions = []
        (
            totalized_exclusions.extend(
                map(lambda elem: Exclusions(**elem), config_tool.exclusions_all)
            )
            if config_tool.exclusions_all is not None
            else None
        )
        (
            totalized_exclusions.extend(
                map(lambda elem: Exclusions(**elem), config_tool.exclusions_scope)
            )
            if config_tool.exclusions_scope is not None
            else None
        )

        input_core = InputCore(
            totalized_exclusions=totalized_exclusions,
            threshold_defined=config_tool.threshold,
            path_file_results=path_file_results,
            custom_message_break_build=config_tool.message_info_engine_iac,
            scope_pipeline=config_tool.scope_pipeline,
            stage_pipeline=self.devops_platform_gateway.get_variable("stage").capitalize(),
        )

        return findings_list, input_core

    def complete_config_tool(self, data_file_tool, exclusions, tool, dict_args):
        config_tool = ConfigTool(json_data=data_file_tool, tool=tool)
        skip_tool = "false"

        config_tool.exclusions = exclusions
        config_tool.scope_pipeline = self.devops_platform_gateway.get_variable(
            "pipeline_name"
        )

        if config_tool.exclusions.get("All") is not None:
            config_tool.exclusions_all = config_tool.exclusions.get("All").get(tool)
        if config_tool.exclusions.get(config_tool.scope_pipeline) is not None:
            config_tool.exclusions_scope = config_tool.exclusions.get(
                config_tool.scope_pipeline
            ).get(tool)
            skip_tool = "true" if config_tool.exclusions.get(config_tool.scope_pipeline).get("SKIP_TOOL") else "false"
        if(dict_args["folder_path"]):
            folders_to_scan = [dict_args["folder_path"]]
        else:
            folders_to_scan = self.search_folders(
                config_tool.search_pattern, config_tool.ignore_search_pattern
            )

        if len(folders_to_scan) == 0:
            logger.warning(
                "No folders found with the search pattern: %s",
                config_tool.search_pattern,
            )

        return config_tool, folders_to_scan, skip_tool

    def search_folders(self, search_pattern, ignore_pattern):
        current_directory = os.getcwd()
        patron = (
            "(?i)(?!.*(?:"
            + "|".join(ignore_pattern)
            + ")).*?("
            + "|".join(search_pattern)
            + ").*$"
        )
        folders = [
            folder
            for folder in os.listdir(current_directory)
            if os.path.isdir(os.path.join(current_directory, folder))
        ]
        matching_folders = [
            os.path.normpath(os.path.join(current_directory, folder))
            for folder in folders
            if re.match(patron, folder)
        ]
        return matching_folders
