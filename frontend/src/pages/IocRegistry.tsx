import { useEffect, useState } from "react";
import {
  Button,
  Card,
  Input,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  DeleteOutlined,
  DownloadOutlined,
  ReloadOutlined,
  SearchOutlined,
} from "@ant-design/icons";
import dayjs from "dayjs";
import apiClient from "../api/client";

const { Text } = Typography;

interface IocItem {
  id: number;
  type: string;
  value: string;
  source: string;
  reputation: string;
  status: string;
  created_at: string;
}

const IOC_TYPES = [
  { value: "IP", label: "IP" },
  { value: "Domain", label: "Domain" },
  { value: "URL", label: "URL" },
  { value: "MD5", label: "MD5" },
  { value: "SHA1", label: "SHA1" },
  { value: "SHA256", label: "SHA256" },
];

const IOC_STATUSES = [
  { value: "Активен", label: "Активен" },
  { value: "Заблокирован", label: "Заблокирован" },
  { value: "Ложное срабатывание", label: "Ложное срабатывание" },
];

const TYPE_COLORS: Record<string, string> = {
  IP: "volcano",
  Domain: "orange",
  URL: "gold",
  MD5: "purple",
  SHA1: "geekblue",
  SHA256: "blue",
};

export default function IocRegistry() {
  const [items, setItems] = useState<IocItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [typeFilter, setTypeFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [searchQuery, setSearchQuery] = useState("");

  const fetchIocs = async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = {};
      if (typeFilter) params.ioc_type = typeFilter;
      if (statusFilter) params.status = statusFilter;
      if (searchQuery.trim()) params.q = searchQuery.trim();

      const response = await apiClient.get<IocItem[]>("/iocs/", { params });
      setItems(response.data);
    } catch {
      message.error("Не удалось загрузить реестр индикаторов");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIocs();
  }, [typeFilter, statusFilter]);

  const handleStatusChange = async (id: number, newStatus: string) => {
    try {
      await apiClient.patch(`/iocs/${id}`, { status: newStatus });
      setItems((prev) =>
        prev.map((item) => (item.id === id ? { ...item, status: newStatus } : item))
      );
      message.success("Статус индикатора обновлён");
    } catch {
      message.error("Ошибка при обновлении статуса");
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await apiClient.delete(`/iocs/${id}`);
      setItems((prev) => prev.filter((item) => item.id !== id));
      message.success("Индикатор удалён");
    } catch {
      message.error("Не удалось удалить индикатор");
    }
  };

  const handleExport = async () => {
    try {
      const params: Record<string, string> = {};
      if (typeFilter) params.ioc_type = typeFilter;
      if (statusFilter) params.status = statusFilter;

      const response = await apiClient.get("/iocs/export", {
        params,
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "ioc_blocklist.txt");
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      message.error("Ошибка при экспорте блоклиста");
    }
  };

  const columns: ColumnsType<IocItem> = [
    {
      title: "Тип",
      dataIndex: "type",
      key: "type",
      width: 110,
      render: (type: string) => <Tag color={TYPE_COLORS[type] || "default"}>{type}</Tag>,
    },
    {
      title: "Значение",
      dataIndex: "value",
      key: "value",
      render: (value: string) => (
        <Text code copyable style={{ wordBreak: "break-all" }}>
          {value}
        </Text>
      ),
    },
    {
      title: "Источник (письмо)",
      dataIndex: "source",
      key: "source",
      width: 220,
    },
    {
      title: "Репутация",
      dataIndex: "reputation",
      key: "reputation",
      width: 140,
      render: (rep: string) => (
        <Tag color={rep === "Вредоносный" ? "error" : "default"}>{rep}</Tag>
      ),
    },
    {
      title: "Статус",
      dataIndex: "status",
      key: "status",
      width: 210,
      render: (status: string, record) => (
        <Select
          size="small"
          value={status}
          options={IOC_STATUSES}
          style={{ width: "100%" }}
          onChange={(val) => handleStatusChange(record.id, val)}
        />
      ),
    },
    {
      title: "Добавлен",
      dataIndex: "created_at",
      key: "created_at",
      width: 150,
      render: (val: string) => dayjs(val).format("DD.MM.YYYY HH:mm"),
    },
    {
      title: "",
      key: "actions",
      width: 60,
      render: (_, record) => (
        <Popconfirm
          title="Удалить индикатор?"
          onConfirm={() => handleDelete(record.id)}
          okText="Да"
          cancelText="Нет"
        >
          <Button type="text" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <Card
      title="Реестр индикаторов компрометации (IOC)"
      extra={
        <Space wrap>
          <Input
            placeholder="Поиск по значению или письму..."
            prefix={<SearchOutlined />}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onPressEnter={fetchIocs}
            allowClear
            style={{ width: 250 }}
          />
          <Select
            placeholder="Тип IOC"
            allowClear
            options={IOC_TYPES}
            value={typeFilter}
            onChange={setTypeFilter}
            style={{ width: 130 }}
          />
          <Select
            placeholder="Статус"
            allowClear
            options={IOC_STATUSES}
            value={statusFilter}
            onChange={setStatusFilter}
            style={{ width: 180 }}
          />
          <Button icon={<ReloadOutlined />} onClick={fetchIocs} loading={loading}>
            Обновить
          </Button>
          <Button type="primary" icon={<DownloadOutlined />} onClick={handleExport}>
            Экспорт блоклиста
          </Button>
        </Space>
      }
    >
      <Table
        rowKey="id"
        columns={columns}
        dataSource={items}
        loading={loading}
        pagination={{ pageSize: 20, showSizeChanger: true }}
        locale={{ emptyText: "Индикаторы не найдены" }}
      />
    </Card>
  );
}
