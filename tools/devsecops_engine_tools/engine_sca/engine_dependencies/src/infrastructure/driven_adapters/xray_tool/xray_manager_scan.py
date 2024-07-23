from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import subprocess
import platform
import requests
import re
import os
import json
import shutil

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class XrayScan(ToolGateway):
    def install_tool_linux(self, version):
        installed = subprocess.run(
            ["which", "./jf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", "./jf"]
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf"
                file = "./jf"
                response = requests.get(url, allow_redirects=True)
                with open(file, "wb") as archivo:
                    archivo.write(response.content)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error during Jfrog Cli installation on Linux: {error}")

    def install_tool_windows(self, version):
        try:
            subprocess.run(
                ["./jf.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe"
                exe_file = "./jf.exe"
                response = requests.get(url, allow_redirects=True)
                with open(exe_file, "wb") as archivo:
                    archivo.write(response.content)
            except subprocess.CalledProcessError as error:
                logger.error(f"Error while Jfrog Cli installation on Windows: {error}")

    def install_tool_darwin(self, version):
        installed = subprocess.run(
            ["which", "./jf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", "./jf"]
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-mac-386/jf"
                file = "./jf"
                response = requests.get(url, allow_redirects=True)
                with open(file, "wb") as archivo:
                    archivo.write(response.content)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error during Jfrog Cli installation on Darwin: {error}")

    def config_server(self, prefix, token):
        try:
            c_import = [prefix, "c", "im", token]
            result = subprocess.run(
                c_import,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            server_id = re.search(r"'(.*?)'", result.stderr).group(1)
            c_set_server = [prefix, "c", "use", server_id]
            subprocess.run(
                c_set_server,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            logger.error(f"Error during Xray Server configuration: {error}")

    def config_audit_scan(self, prefix, to_scan):
        gradlew_path = os.path.join(to_scan, "gradlew")
        if os.path.exists(gradlew_path):
            os.chmod(gradlew_path, 0o755)
        destination_path = os.path.join(to_scan, os.path.basename(prefix))
        if not os.path.exists(destination_path):
            shutil.move(prefix, destination_path)

    def scan_dependencies(self, prefix, cwd, mode, to_scan):
        command = [
            prefix,
            mode,
            "--format=json",
            f"{to_scan}",
        ]
        result = subprocess.run(
            command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            scan_result = json.loads(result.stdout)
            file_result = os.path.join(os.getcwd(), "scan_result.json")
            with open(file_result, "w") as file:
                json.dump(scan_result, file, indent=4)
            return file_result
        else:
            logger.error(f"Error executing jf scan: {result.stderr}")
            return None

    def run_tool_dependencies_sca(
        self,
        remote_config,
        dict_args,
        to_scan,
        token,
    ):
        cli_version = remote_config["XRAY"]["CLI_VERSION"]
        os_platform = platform.system()

        if os_platform == "Linux":
            self.install_tool_linux(cli_version)
            command_prefix = "./jf"
        elif os_platform == "Windows":
            self.install_tool_windows(cli_version)
            command_prefix = "./jf.exe"
        elif os_platform == "Darwin":
            command_prefix = "./jf"
            self.install_tool_darwin(cli_version)
        else:
            logger.warning(f"{os_platform} is not supported.")
            return None

        self.config_server(command_prefix, token)

        cwd = os.getcwd()
        if dict_args["xray_mode"] == "audit":
            if os.path.exists(to_scan):
                self.config_audit_scan(command_prefix, to_scan)
                cwd = to_scan
                to_scan = ""
            else:
                logger.warning(f"No such file or directory: {to_scan}")
                return None

        results_file = self.scan_dependencies(
            command_prefix,
            cwd,
            dict_args["xray_mode"],
            to_scan,
        )

        return results_file
