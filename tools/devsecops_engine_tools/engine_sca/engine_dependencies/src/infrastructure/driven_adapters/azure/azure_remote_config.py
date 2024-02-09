from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
    ReleaseVariables,
    BuildVariables,
)
from devsecops_engine_utilities.azuredevops.infrastructure.azure_devops_api import (
    AzureDevopsApi,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.config_gateway import (
    ConfigGateway,
)


class AzureRemoteConfig(ConfigGateway):
    def get_remote_config(self, dict_args, file_path):
        base_compact_remote_config_url = (
            f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
            f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_git/"
            f"{dict_args['remote_config_repo']}?path=/"
        )
        utils_azure = AzureDevopsApi(
            personal_access_token=SystemVariables.System_AccessToken.value(),
            compact_remote_config_url=f"{base_compact_remote_config_url}" + file_path,
        )
        connection = utils_azure.get_azure_connection()
        return utils_azure.get_remote_json_config(connection=connection)

    def get_variable(self, variable):
        try:
            if variable == "pipeline_name":
                return BuildVariables.Build_DefinitionName.value()
        except Exception as ex:
            print(self.logging("info", str(ex)))
            return None
