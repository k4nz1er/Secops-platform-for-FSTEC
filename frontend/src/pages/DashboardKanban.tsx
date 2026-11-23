import { useEffect, useState } from "react";
import {
  Button,
  Card,
  Col,
  Empty,
  Form,
  Input,
  Modal,
  Progress,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Tag,
  Typography,
  message,
} from "antd";
import {
  BugOutlined,
  CalendarOutlined,
  CheckCircleOutlined,
  EditOutlined,
  RadarChartOutlined,
  ReloadOutlined,
  UserOutlined,
} from "@ant-design/icons";
import dayjs from "dayjs";
import apiClient from "../api/client";

const { Text, Paragraph } = Typography;
const { TextArea } = Input;

interface KanbanCard {
  task_id: number;
  vulnerability_id: number;
  source_document: string | null;
  bdu: string | null;
  cve: string | null;
  description: string;
  action_taken: string;
  assignee_id: number;
  assignee_name: string;
  deadline: string;
  status: string;
}

interface DashboardMetrics {
  total_tasks: number;
  total_vulnerabilities: number;
  total_iocs: number;
  completion_percentage: number;
}

interface DashboardState {
  metrics: DashboardMetrics;
  columns: {
    in_progress: KanbanCard[];
    closed: KanbanCard[];
  };
}

const STATUS_OPTIONS = [
  { value: "В работе", label: "В работе" },
  { value: "Выполнена", label: "Выполнена" },
  { value: "Закрыта", label: "Закрыта" },
];

export default function DashboardKanban() {
  const [data, setData] = useState<DashboardState | null>(null);
  const [loading, setLoading] = useState(true);
  const [editingCard, setEditingCard] = useState<KanbanCard | null>(null);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get<DashboardState>("/kanban/dashboard");
      setData(response.data);
    } catch {
      message.error("Не удалось загрузить данные дашборда");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  const openEditModal = (card: KanbanCard) => {
    setEditingCard(card);
    form.setFieldsValue({
      status: card.status,
      action_taken: card.action_taken,
    });
  };

  const handleSave = async () => {
    if (!editingCard) return;
    try {
      const values = await form.validateFields();
      setSaving(true);
      await apiClient.patch(`/kanban/tasks/${editingCard.task_id}`, {
        status: values.status,
        action_taken: values.action_taken,
      });
      message.success("Задача обновлена");
      setEditingCard(null);
      fetchDashboard();
    } catch {
      message.error("Ошибка при обновлении задачи");
    } finally {
      setSaving(false);
    }
  };

  const renderCard = (card: KanbanCard) => {
    const isOverdue =
      card.status === "В работе" && dayjs(card.deadline).isBefore(dayjs(), "day");

    return (
      <Card
        key={card.task_id}
        size="small"
        style={{ marginBottom: 12 }}
        title={
          <Space wrap size={[4, 4]}>
            <Tag color="blue">{card.bdu || "Без БДУ"}</Tag>
            {card.cve && <Tag color="volcano">{card.cve}</Tag>}
          </Space>
        }
        extra={
          <Button
            type="link"
            size="small"
            icon={<EditOutlined />}
            onClick={() => openEditModal(card)}
          >
            Изменить
          </Button>
        }
      >
        <Space direction="vertical" size={6} style={{ width: "100%" }}>
          {card.source_document && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              Документ: {card.source_document}
            </Text>
          )}

          <Paragraph ellipsis={{ rows: 3, expandable: true, symbol: "ещё" }} style={{ marginBottom: 4 }}>
            {card.description || "Описание отсутствует"}
          </Paragraph>

          {card.action_taken && (
            <Text style={{ fontSize: 12 }}>
              <Text strong>Что сделано: </Text>
              {card.action_taken}
            </Text>
          )}

          <Space
            style={{
              width: "100%",
              justifyContent: "space-between",
              marginTop: 6,
              paddingTop: 6,
              borderTop: "1px solid #f0f0f0",
            }}
          >
            <Text type="secondary" style={{ fontSize: 12 }}>
              <UserOutlined /> {card.assignee_name}
            </Text>
            <Tag color={isOverdue ? "error" : "default"} icon={<CalendarOutlined />}>
              {dayjs(card.deadline).format("DD.MM.YYYY")}
            </Tag>
          </Space>
        </Space>
      </Card>
    );
  };

  if (loading && !data) {
    return (
      <div style={{ textAlign: "center", padding: "80px 0" }}>
        <Spin size="large" />
      </div>
    );
  }

  const metrics = data?.metrics;
  const inProgress = data?.columns.in_progress ?? [];
  const closed = data?.columns.closed ?? [];

  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Всего задач"
              value={metrics?.total_tasks ?? 0}
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Уязвимости в реестре"
              value={metrics?.total_vulnerabilities ?? 0}
              prefix={<BugOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Индикаторы (IOC)"
              value={metrics?.total_iocs ?? 0}
              prefix={<RadarChartOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Text type="secondary">Прогресс отработки</Text>
            <div style={{ marginTop: 8 }}>
              <Progress percent={Math.round(metrics?.completion_percentage ?? 0)} status="active" />
            </div>
          </Card>
        </Col>
      </Row>

      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <Button icon={<ReloadOutlined />} onClick={fetchDashboard} loading={loading}>
          Обновить доску
        </Button>
      </div>

      <Row gutter={[16, 16]} align="top">
        <Col xs={24} lg={12}>
          <Card
            title={`В работе (${inProgress.length})`}
            headStyle={{ background: "#fafafa" }}
          >
            {inProgress.length > 0 ? (
              inProgress.map(renderCard)
            ) : (
              <Empty description="Активных задач нет" />
            )}
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card
            title={`Выполнено / Закрыто (${closed.length})`}
            headStyle={{ background: "#f6ffed" }}
          >
            {closed.length > 0 ? (
              closed.map(renderCard)
            ) : (
              <Empty description="Завершённых задач пока нет" />
            )}
          </Card>
        </Col>
      </Row>

      <Modal
        title={`Задача #${editingCard?.task_id} (${editingCard?.bdu || "Без БДУ"})`}
        open={Boolean(editingCard)}
        onOk={handleSave}
        onCancel={() => setEditingCard(null)}
        confirmLoading={saving}
        okText="Сохранить"
        cancelText="Отмена"
      >
        <Form form={form} layout="vertical">
          <Form.Item name="status" label="Статус" rules={[{ required: true }]}>
            <Select options={STATUS_OPTIONS} />
          </Form.Item>
          <Form.Item name="action_taken" label="Что сделано">
            <TextArea
              rows={4}
              placeholder="Опишите принятые меры (установка патча, блокировка IOC, проверка хостов)..."
            />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
