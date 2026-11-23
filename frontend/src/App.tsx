import { useEffect, useState } from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  ConfigProvider,
  Layout,
  Menu,
  Space,
  Spin,
  Tag,
  Typography,
  theme,
} from "antd";
import type { MenuProps } from "antd";
import ruRU from "antd/locale/ru_RU";
import {
  BugOutlined,
  DashboardOutlined,
  SafetyCertificateOutlined,
  UploadOutlined,
  UserOutlined,
} from "@ant-design/icons";
import keycloak from "./services/keycloak";
import DashboardKanban from "./pages/DashboardKanban";
import Vulnerabilities from "./pages/Vulnerabilities";
import IocRegistry from "./pages/IocRegistry";
import DocumentUpload from "./pages/DocumentUpload";

const BRAND_LOGO = "/opt/secops-platform/frontend/public/NPP_Pulsars.png";          // файл из /opt/secops-platform/frontend/public/
const BRAND_TITLE = "SecOpsCenter";
const BRAND_SUBTITLE = "";

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();

  const username =
    (keycloak.tokenParsed?.preferred_username as string) || "Специалист ИБ";

  const menuItems: MenuProps["items"] = [
    {
      key: "/",
      icon: <DashboardOutlined />,
      label: "Аналитика",
    },
    {
      key: "/vulnerabilities",
      icon: <BugOutlined />,
      label: "Реестр БДУ / CVE",
    },
    {
      key: "/iocs",
      icon: <SafetyCertificateOutlined />,
      label: "Индикаторы (IOC)",
    },
    {
      key: "/upload",
      icon: <UploadOutlined />,
      label: "Загрузка файлов",
    },
  ];

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider width={248} className="cp-sider">
        <div className="cp-brand">
          <img
            src={BRAND_LOGO}
            alt="logo"
            onError={(e) => {
              e.currentTarget.style.display = "none";
            }}
            style={{
              width: 36,
              height: 36,
              objectFit: "contain",
              flexShrink: 0,
            }}
          />
          <div style={{ overflow: "hidden" }}>
            <Text
              strong
              ellipsis
              style={{
                color: "#fcee0a",
                fontSize: 15,
                letterSpacing: "0.06em",
                display: "block",
                lineHeight: 1.2,
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
              }}
            >
              {BRAND_TITLE}
            </Text>
            {BRAND_SUBTITLE && (
              <Text
                ellipsis
                style={{
                  color: "#00f0ff",
                  fontSize: 11,
                  letterSpacing: "0.04em",
                  display: "block",
                  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
                }}
              >
                {BRAND_SUBTITLE}
              </Text>
            )}
          </div>
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ marginTop: 10 }}
        />
      </Sider>

      <Layout>
        <Header
          className="cp-header"
          style={{
            padding: "0 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <Text
            strong
            style={{
              fontSize: 14,
              letterSpacing: "0.05em",
              textTransform: "uppercase",
              color: "#e8eef8",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
            }}
          >
            Обработка бюллетеней ФСТЭК / НКЦКИ и IOC
          </Text>

          <Space size="middle">
            <Tag
              icon={<UserOutlined />}
              style={{
                background: "rgba(252, 238, 10, 0.12)",
                borderColor: "#fcee0a",
                color: "#fcee0a",
                marginRight: 0,
                textTransform: "uppercase",
              }}
            >
              {username}
            </Tag>
          </Space>
        </Header>

        <Content style={{ margin: 20 }}>
          <Routes>
            <Route path="/" element={<DashboardKanban />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/iocs" element={<IocRegistry />} />
            <Route path="/upload" element={<DocumentUpload />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  );
}

export default function App() {
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    document.title = BRAND_TITLE;
  }, []);

  useEffect(() => {
    keycloak
      .init({
        onLoad: "login-required",
        checkLoginIframe: false,
      })
      .then(() => setInitialized(true))
      .catch(() => setInitialized(true));
  }, []);

  if (!initialized) {
    return (
      <div
        style={{
          height: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#07080d",
        }}
      >
        <Spin size="large" tip="Загрузка..." />
      </div>
    );
  }

  return (
    <ConfigProvider
      locale={ruRU}
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: "#fcee0a",
          colorInfo: "#00f0ff",
          colorError: "#ff003c",
          colorWarning: "#ffb800",
          colorSuccess: "#00ff9f",
          colorBgBase: "#07080d",
          colorBgLayout: "#07080d",
          colorBgContainer: "#0d101b",
          colorBgElevated: "#131829",
          colorBorder: "#1e2942",
          colorBorderSecondary: "#1e2942",
          colorText: "#e8eef8",
          colorTextSecondary: "#7c8db5",
          borderRadius: 0,
        },
        components: {
          Button: {
            primaryColor: "#050608",
          },
          Pagination: {
            itemActiveBg: "#131829",
          },
        },
      }}
    >
      <BrowserRouter>
        <AppLayout />
      </BrowserRouter>
    </ConfigProvider>
  );
}
