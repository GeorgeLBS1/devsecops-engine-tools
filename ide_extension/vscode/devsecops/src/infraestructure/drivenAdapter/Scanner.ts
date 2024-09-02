import { OutputChannel } from "vscode";
import IScannerGateway from "../../domain/model/gateways/IScannerGateway";
import {exec} from 'child_process';
import OutputManager from "../helper/OutputManager";

export class Scanner implements IScannerGateway{

    iacScan(folderToScan: string, outputChannel: OutputChannel): void {
        exec(`docker run --rm -v ${folderToScan}:/ms_artifact bancolombia/devsecops-engine-tools:1.8.7  devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --tool engine_iac --folder_path /ms_artifact`, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                console.error(`stderr: ${stderr}`);
                return;
            }

            const cleanedOutput = OutputManager.removeAnsiEscapeCodes(stdout);
            outputChannel.appendLine('IaC Scan Output:');
            outputChannel.appendLine(cleanedOutput);
            outputChannel.show();
        });
    }

}