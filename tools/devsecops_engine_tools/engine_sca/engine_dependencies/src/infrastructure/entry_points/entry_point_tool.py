from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core import (
    SetInputCore,
)

def init_engine_sca_rm(
    tool_run, tool_remote, tool_deserializator, dict_args, token
):
    dependencies_sca_scan = DependenciesScan(
        tool_run, tool_remote, tool_deserializator, dict_args, token
    )
    input_core = SetInputCore(tool_remote, dict_args)
    dependencies_scanned = dependencies_sca_scan.process()
    deserialized = dependencies_sca_scan.deserializator(dependencies_scanned)
    core_input = input_core.set_input_core(dependencies_scanned)

    return deserialized, core_input