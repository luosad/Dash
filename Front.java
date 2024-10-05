import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.concurrent.Task;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class Front extends Application {

    private Label qoeBeforeLabel;
    private Label qoeAfterLabel;

    @Override
    public void start(Stage primaryStage) {
        Button startButton = new Button("开始抓包");
        qoeBeforeLabel = new Label("流量整形前QoE结果: ");
        qoeAfterLabel = new Label("流量整形后QoE结果: ");

        startButton.setOnAction(event -> startCapture());

        VBox vbox = new VBox(10, startButton, qoeBeforeLabel, qoeAfterLabel);
        Scene scene = new Scene(vbox, 300, 200);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Dash评估系统");
        primaryStage.show();
    }

    private void startCapture() {
        Task<Void> captureTask = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                // 使用 tcpdump 抓包并保存为 output.pcap
                String command = "tcpdump -i any -w output.pcap"; // 根据实际情况修改接口
                Process process = Runtime.getRuntime().exec(command);
                // 等待一段时间（根据实际情况调整）
                Thread.sleep(5000); // 假设抓包持续5秒
                process.destroy(); // 停止 tcpdump
                return null;
            }

            @Override
            protected void succeeded() {
                // 抓包完成后获取 QoE 结果
                fetchQoEResults();
            }
        };
        new Thread(captureTask).start();
    }

    private void fetchQoEResults() {
        Task<String[]> qoeTask = new Task<String[]>() {
            @Override
            protected String[] call() throws Exception {
                String[] results = new String[2];
                // 假设你的后端 Python 服务在 localhost:5000 上
                results[0] = sendRequest("http://localhost:5000/getQoEResults?type=before");
                results[1] = sendRequest("http://localhost:5000/getQoEResults?type=after");
                return results;
            }
        };

        qoeTask.setOnSucceeded(event -> {
            String[] results = qoeTask.getValue();
            Platform.runLater(() -> {
                qoeBeforeLabel.setText("流量整形前QoE结果: " + results[0]);
                qoeAfterLabel.setText("流量整形后QoE结果: " + results[1]);
            });
        });

        new Thread(qoeTask).start();
    }

    private String sendRequest(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            if (conn.getResponseCode() == 200) {
                StringBuilder response = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                }
                return response.toString();
            } else {
                return "请求失败，状态码: " + conn.getResponseCode();
            }
        } catch (IOException e) {
            return "请求异常: " + e.getMessage();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
