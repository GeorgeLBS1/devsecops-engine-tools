package co.com.bancolombia.devsecopsenginetools.actions;

import co.com.bancolombia.devsecopsenginetools.tasks.ScanIacTask;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.project.Project;
import lombok.SneakyThrows;

public class ScanIacAction extends AnAction {

    @SneakyThrows
    @Override
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getProject();
        LogPanelLogger.activate(project);
        if (project != null) {
            ScanIacTask task = new ScanIacTask(project, "Scanning iac");
            ProgressManager.getInstance().run(task);
        }
    }
}