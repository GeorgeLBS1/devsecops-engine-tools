package co.com.bancolombia.devsecopsenginetools.tasks;

import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.Commands;
import co.com.bancolombia.devsecopsenginetools.utils.DataUtils;
import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.NlsContexts;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class ScanIacTask extends Task.Backgroundable {
    public ScanIacTask(@Nullable Project project, @NlsContexts.ProgressTitle @NotNull String title) {
        super(project, title, false);
    }

    @Override
    public void run(@NotNull ProgressIndicator progressIndicator) {
        try {
            LogPanelLogger.clear();
            prepareFiles(requireNonNull(myProject));
            String command = GlobalSettings.getInstance().getScanIacCommand()
                    .replace("{projectPath}", requireNonNull(myProject.getBasePath()));
            LogPanelLogger.info("Running scan IaC command: " + command);
            Commands.runCommand(command, LogPanelLogger::info);
        } catch (Exception ex) {
            LogPanelLogger.error("Error running scan IaC command: ", ex);
        }
    }

    private void prepareFiles(Project project) throws IOException {
        String projectPath = project.getBasePath() != null ? project.getBasePath() : "";
        Path iacDestination = Path.of(projectPath, "build", "dev-sec-ops", "iac");
        Files.createDirectories(iacDestination);
        FileUtils.deleteDirectory(iacDestination);
        ProjectSettings settings = ProjectSettingsUtils.getProjectSettings(project);
        for (String source : settings.getIacDirectory().split(",")) {
            Path iacSource = Path.of(projectPath, source);
            LogPanelLogger.info("Copying IaC files from " + iacSource + " to " + iacDestination);
            FileUtils.copyDirectory(iacSource, iacDestination);
        }
        if (settings.isReplaceTokens()) {
            LogPanelLogger.info("Replacing tokens in IaC files");
            Map<String, String> env = FileUtils.readEnvFile(Path.of(projectPath, settings.getDotEnvFile()));
            FileUtils.walkDirectory(iacDestination, content ->
                    DataUtils.replaceTokens(content, settings.getReplacePattern(), env));
        }
    }
}