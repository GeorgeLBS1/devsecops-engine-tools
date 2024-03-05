from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core import (
    SetInputCore,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns import (
    HandleRemoteConfigPatterns,
)
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.find_mono_repos import (
    FindMonoRepos,
)

import os


def init_engine_dependencies(
    tool_run, tool_remote, tool_deserializator, dict_args, token, tool
):
    handle_remote_config_patterns = HandleRemoteConfigPatterns(tool_remote, dict_args)
    find_mono_repo = FindMonoRepos(tool_remote)

    current_path = os.getcwd()
    mr_path = find_mono_repo.process_find_mono_repo()
    agent_path = handle_remote_config_patterns.process_handle_working_directory()
    if agent_path != current_path:
        current_path = agent_path
    elif mr_path != current_path:
        current_path = mr_path

    dependencies_sca_scan = DependenciesScan(
        tool_run,
        tool_remote,
        tool_deserializator,
        dict_args,
        current_path,
        handle_remote_config_patterns.process_handle_skip_tool(),
        handle_remote_config_patterns.process_handle_analysis_pattern(),
        handle_remote_config_patterns.process_handle_bypass_expression(),
        handle_remote_config_patterns.process_handle_excluded_files(),
        token,
    )
    input_core = SetInputCore(tool_remote, dict_args, tool)
    dependencies_scanned = dependencies_sca_scan.process()
    if dependencies_scanned:
        deserialized = dependencies_sca_scan.deserializator(dependencies_scanned)
    else:
        deserialized = []
    core_input = input_core.set_input_core(dependencies_scanned)

    return deserialized, core_input