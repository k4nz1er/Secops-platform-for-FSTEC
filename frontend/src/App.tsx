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
  Button,
  ConfigProvider,
  Layout,
  Menu,
  Space,
  Spin,
  Tag,
  Tooltip,
  Typography,
  theme,
} from "antd";
import type { MenuProps } from "antd";
import ruRU from "antd/locale/ru_RU";
import {
  BugOutlined,
  DashboardOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyCertificateOutlined,
  UploadOutlined,
  UserOutlined,
} from "@ant-design/icons";
import keycloak from "./services/keycloak";
import DashboardKanban from "./pages/DashboardKanban";
import Vulnerabilities from "./pages/Vulnerabilities";
import IocRegistry from "./pages/IocRegistry";
import DocumentUpload from "./pages/DocumentUpload";

const BRAND_LOGO = "/NPP_Pulsars.png"; // файл из frontend/public/
const BRAND_TITLE = "SecOpsCenter";
const BRAND_SUBTITLE = "SEC // OPS";
const SIDER_STORAGE_KEY = "secops_sider_collapsed";

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [logoError, setLogoError] = useState(false);
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(SIDER_STORAGE_KEY) === "true";
    } catch {
      return false;
    }
  });

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(SIDER_STORAGE_KEY, String(next));
      } catch {
        // ignore storage errors
      }
      return next;
    });
  };

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
      <Sider
        collapsible
        collapsed={collapsed}
        trigger={null}
        width={244}
        collapsedWidth={68}
        className="ar-sider"
      >
        <div
          className="ar-brand"
          onClick={() => navigate("/")}
          style={{ cursor: "pointer" }}
          title={BRAND_TITLE}
        >
          {!logoError ? (
            <img
              src={BRAND_LOGO}
              alt="logo"
              onError={() => setLogoError(true)}
              style={{
                width: 34,
                height: 34,
                objectFit: "contain",
                flexShrink: 0,
              }}
            />
          ) : (
            <div className="ar-brand-fallback">SC</div>
          )}

          {!collapsed && (
            <div style={{ overflow: "hidden", whiteSpace: "nowrap" }}>
              <Text
                strong
                ellipsis
                style={{
                  color: "#f0f2f5",
                  fontSize: 15,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
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
                    color: "#e6192e",
                    fontSize: 10.5,
                    letterSpacing: "0.14em",
                    fontWeight: 700,
                    display: "block",
                    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
                  }}
                >
                  {BRAND_SUBTITLE}
                </Text>
              )}
            </div>
          )}
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
          className="ar-header"
          style={{
            padding: "0 20px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 16,
          }}
        >
          <Space size={14}>
            <Tooltip title={collapsed ? "Развернуть меню" : "Свернуть меню"}>
              <Button
                type="text"
                className="ar-collapse-btn"
                icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
                onClick={toggleCollapsed}
              />
            </Tooltip>
            <Text
              strong
              style={{
                fontSize: 13.5,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "#f0f2f5",
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
              }}
            >
              Обработка бюллетеней ФСТЭК / НКЦКИ и IOC
            </Text>
          </Space>

          <Space size="middle">
            <Tag
              icon={<UserOutlined />}
              style={{
                background: "rgba(230, 25, 46, 0.14)",
                borderColor: "#e6192e",
                color: "#f0f2f5",
                marginRight: 0,
                textTransform: "uppercase",
                letterSpacing: "0.05em",
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
          background: "#070709",
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
          colorPrimary: "#e6192e",
          colorInfo: "#e6192e",
          colorError: "#ff2a3c",
          colorWarning: "#d97706",
          colorSuccess: "#10b981",
          colorBgBase: "#070709",
          colorBgLayout: "#070709",
          colorBgContainer: "#0e0f13",
          colorBgElevated: "#16181f",
          colorBorder: "#262832",
          colorBorderSecondary: "#262832",
          colorText: "#f0f2f5",
          colorTextSecondary: "#8a8f9e",
          borderRadius: 0,
        },
        components: {
          Button: {
            primaryColor: "#ffffff",
          },
          Pagination: {
            itemActiveBg: "#16181f",
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
