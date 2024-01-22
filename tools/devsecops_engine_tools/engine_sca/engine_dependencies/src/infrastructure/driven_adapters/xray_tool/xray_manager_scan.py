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
import tarfile

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class XrayScan(ToolGateway):
    def install_tool_linux(self, version):
        installed = subprocess.run(
            ["which", "./jf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command1 = [
                "wget",
                f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf"
            ]
            command2 = [
                "chmod",
                "+x",
                "./jf"
            ]
            try:
                subprocess.run(
                        command1, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                subprocess.run(
                        command2, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error al instalar Jfrog Cli en Linux: {error}")
        

    def install_tool_windows(self, version):
        try:
            subprocess.run(
                ["./jf.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                url = f'https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe'
                exe_file = './jf.exe'
                response = requests.get(url, allow_redirects=True)
                with open(exe_file, 'wb') as archivo:
                    archivo.write(response.content)
            except subprocess.CalledProcessError as error:
                logger.error(f"Error al instalar Jfrog Cli en Windows: {error}")

    def config_server(self, prefix, token):
        try:
            c_import = [
                prefix,
                "c",
                "im",
                token
            ]
            result = subprocess.run(
                c_import, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            server_id = re.search(r"'(.*?)'", result.stderr).group(1)
            c_set_server = [
                prefix,
                "c",
                "use",
                server_id
            ]
            subprocess.run(
                c_set_server, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        except subprocess.CalledProcessError as error:
            logger.error(f"Error al configurar xray server: {error}")

    def compress_and_mv(self, npm_modules, target_dir):
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        try:
            with tarfile.open(os.path.join(target_dir, "node_modules.tar"), "w") as tar:
                tar.add(npm_modules, arcname=os.path.basename(npm_modules),
                    filter=lambda x: None if '/.bin/' in x.name else x)

        except subprocess.CalledProcessError as e:
            logger.error(f"Error al comprimir npm_modules: {e}")

    def find_artifacts(self, pattern, working_dir, target_dir):
        finded_files = []
        extension_pattern = re.compile(pattern, re.IGNORECASE)
        for root, dirs, files in os.walk(working_dir):
            for file in files:
                if extension_pattern.search(file):
                    ruta_completa = os.path.join(root, file)
                    finded_files.append(ruta_completa)

        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        for file in finded_files:
            target = os.path.join(target_dir, os.path.basename(file))
            if not os.path.exists(target):
                shutil.copy2(file, target)

    def scan_dependencies(self, prefix, target_dir_name):
        try:
            command = [
                prefix,
                "scan",
                "--format=simple-json",
                f"./{target_dir_name}/"
            ]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            scan_result = json.loads(result.stdout)
            file_result = 'scan_result.json'
            with open(file_result, 'w') as file:
                json.dump(scan_result, file, indent=4)
            return file_result
        except subprocess.CalledProcessError as error:
            logger.error(f"Error al escanear dependencias: {error}")

    def run_tool_dependencies_sca(self, remote_config, token):
        cli_version = remote_config["JFROG"]["CLI_VERSION"]
        os_platform = platform.system()

        if os_platform == "Linux":
            self.install_tool_linux(cli_version)
            command_prefix = "./jf"
        elif os_platform == "Windows":
            self.install_tool_windows(cli_version)
            command_prefix = "./jf.exe"

        self.config_server(command_prefix, token)

        working_dir = os.getcwd()
        pattern = remote_config["REGEX_EXPRESSION_EXTENSIONS"]
        dir_to_scan = "dependencies_to_scan"
        dir_to_scan_path = os.path.join(working_dir, dir_to_scan)
        npm_modules_path = os.path.join(working_dir, "node_modules")

        if os.path.exists(npm_modules_path):
            self.compress_and_mv(npm_modules_path, dir_to_scan_path)
        else:
            self.find_artifacts(pattern, working_dir, dir_to_scan_path)
        results_file = self.scan_dependencies(command_prefix, dir_to_scan)

        return results_file