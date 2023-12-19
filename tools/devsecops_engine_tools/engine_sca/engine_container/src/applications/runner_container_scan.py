import sys
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool import (init_engine_sca_rm, get_inputs_from_config_file
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageResultPipeline,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan import ( PrismaCloudManagerScan)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.docker.docker_images import (DockerImages)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_deserialize_output import (PrismaDeserealizator)

def runner_engine_container(dict_args, token):
    try:
        # (
        #     #remote_config_repo,
        #     remote_config_path,
        #     environment,
        # ) = (
        #     #remote_config_repo,
        #     #remote_config_path,
        #     environment or get_inputs_from_config_file(),
        # )
        tool_run = PrismaCloudManagerScan()
        tool_images = DockerImages()
        tool_deseralizator = PrismaDeserealizator()
        return init_engine_sca_rm(tool_run,
            tool_images,
            tool_deseralizator,
            dict_args,
            token
        )
    
    except Exception as e:
        print(AzureMessageResultPipeline.Succeeded.value)
        raise Exception(f"Error SCAN : {str(e)}")
        # Manejar el error según sea necesario


if __name__ == "__main__":
    runner_engine_container()
