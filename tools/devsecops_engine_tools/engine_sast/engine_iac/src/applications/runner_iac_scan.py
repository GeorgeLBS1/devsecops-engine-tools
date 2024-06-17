from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sast_rm,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool import (
    CheckovTool
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_tool import (
    KubescapeTool
)


def runner_engine_iac(dict_args, tool, secret_tool, devops_platform_gateway, env):
    try:
        # Define driven adapters for gateways
        tool_gateway = None
        if tool == "CHECKOV":
            tool_gateway = CheckovTool()
        elif tool == "KUBESCAPE":
            tool_gateway = KubescapeTool()

        return init_engine_sast_rm(
            devops_platform_gateway=devops_platform_gateway,
            tool_gateway=tool_gateway,
            dict_args=dict_args,
            secret_tool=secret_tool,
            tool=tool,
            env=env,
        )

    except Exception as e:
        raise Exception(f"Error engine_iac : {str(e)}")


if __name__ == "__main__":
    runner_engine_iac()
