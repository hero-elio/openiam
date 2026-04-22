import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { ConfigProvider, App as AntdApp } from "antd";
import zhCN from "antd/locale/zh_CN";
import "antd/dist/reset.css";
import "@/styles.css";
import App from "@/App";

const root = document.getElementById("root");
if (!root) throw new Error("#root element missing");

createRoot(root).render(
  <StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: "#1677ff",
          borderRadius: 4,
        },
      }}
    >
      <AntdApp>
        <BrowserRouter basename="/__admin">
          <App />
        </BrowserRouter>
      </AntdApp>
    </ConfigProvider>
  </StrictMode>,
);
