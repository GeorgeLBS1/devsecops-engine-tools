import json
import re
import subprocess

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import ToolGateway


class TrufflehogRun(ToolGateway):
    def install_tool(self, agent_os, agent_temp_dir) -> any:
        reg_exp_os = r'Windows'
        check_os = re.search(reg_exp_os, agent_os)
        if check_os:
            self.run_install_win(agent_temp_dir)
        else:
            command = (
                f"trufflehog --version"
            )
            result = subprocess.run(command, capture_output=True, shell=True)
            output = result.stderr.strip()
            reg_exp = r'not found'
            check_tool = re.search(reg_exp, output.decode('utf-8'))
            if check_tool:
                self.run_install()
    def run_install(self):
        command = (
            f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        )
        subprocess.run(command, capture_output=True, shell=True)
    def run_install_win(self, agent_temp_dir):
        command_complete = f"powershell -Command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; New-Item -Path {agent_temp_dir} -ItemType Directory -Force; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh' -OutFile {agent_temp_dir}\install_trufflehog.sh; bash {agent_temp_dir}\install_trufflehog.sh -b C:/Trufflehog/bin; $env:Path += ';C:/Trufflehog/bin'; C:/Trufflehog/bin/trufflehog.exe --version"
        process = subprocess.Popen(command_complete, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process.communicate()
    def run_tool_secret_scan(self, system_working_dir, exclude_path, agent_os, agent_work_folder):
        reg_exp_os = r'Windows'
        check_os = re.search(reg_exp_os, agent_os)
        if check_os:
            trufflehog_command = "C:/Trufflehog/bin/trufflehog.exe"
        else:
            trufflehog_command = "trufflehog"
        for i in exclude_path:
            command = (
                f'echo {i} >> {agent_work_folder}/excludedPath.txt'
            )
            subprocess.run(command, shell=True, check=True)
        exclude_path = agent_work_folder + "/excludedPath.txt"
        command = (
            f"{trufflehog_command} filesystem {system_working_dir} --json --exclude-paths {exclude_path} --no-verification"
        )
        result = subprocess.run(command, capture_output=True, shell=True)
        output = result.stdout.decode("utf-8")
        result = self.decode_output(output)
        return result
    def decode_output(self, decode_output):
        result = []
        if decode_output != '':
            object_json = decode_output.strip().split('\n')
            json_list = [json.loads(objeto) for objeto in object_json]
            for json_obj in json_list:
                result.append(json_obj)
        return result