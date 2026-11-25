import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Card,
  Checkbox,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  FileTextOutlined,
  ReloadOutlined,
  SearchOutlined,
  StopOutlined,
} from "@ant-design/icons";
import apiClient from "../api/client";

const { Paragraph, Text } = Typography;
const { TextArea } = Input;

interface VulnerabilityItem {
  id: number;
  bdu: string | null;
  cve: string | null;
  source_document: string | null;
  affected_software: string | null;
  recommendations: string | null;
  description: string;
  action_taken: string;
  status: string;
}

interface GroupHeaderRow {
  rowKey: string;
  isGroupHeader: true;
  source_document: string;
  count: number;
}

interface VulnerabilityRow extends VulnerabilityItem {
  rowKey: string;
  isGroupHeader: false;
  groupIndex: number;
}

type TableRow = GroupHeaderRow | VulnerabilityRow;

const VULN_STATUSES = [
  { value: "В работе", label: "В работе" },
  { value: "Выполнена", label: "Выполнена" },
  { value: "Закрыта", label: "Закрыта" },
];

const NOT_RELEVANT_TEXT = "Не актуально (ПО не используется)";
const NOT_RELEVANT_RE =
  /(не\s*актуал|не\s*примен|не\s*использует|не\s*установл|отсутств|нет\s+по|(?:^|\s)н\/а(?:$|\s|[.,;]))/i;

const isNotRelevant = (actionTaken: string) => NOT_RELEVANT_RE.test(actionTaken || "");

const TOTAL_COLUMNS = 7;

export default function Vulnerabilities() {
  const [items, setItems] = useState<VulnerabilityItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [documentFilter, setDocumentFilter] = useState<string | undefined>();
  const [searchQuery, setSearchQuery] = useState("");
  const [onlyReadyExport, setOnlyReadyExport] = useState(false);
  const [editingItem, setEditingItem] = useState<VulnerabilityItem | null>(null);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const fetchVulnerabilities = async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = {};
      if (statusFilter) params.status = statusFilter;
      if (searchQuery.trim()) params.q = searchQuery.trim();

      const response = await apiClient.get<VulnerabilityItem[]>("/vulnerabilities/", { params });
      setItems(response.data);
    } catch {
      message.error("Не удалось загрузить реестр уязвимостей");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVulnerabilities();
  }, [statusFilter]);

  const uniqueDocuments = useMemo(() => {
    const docs = new Set<string>();
    items.forEach((item) => {
      docs.add(item.source_document?.trim() || "Без номера письма");
    });
    return Array.from(docs);
  }, [items]);

  const tableRows = useMemo<TableRow[]>(() => {
    const filtered = documentFilter
      ? items.filter(
          (item) => (item.source_document?.trim() || "Без номера письма") === documentFilter
        )
      : items;

    const groups = new Map<string, VulnerabilityItem[]>();
    filtered.forEach((item) => {
      const docKey = item.source_document?.trim() || "Без номера письма";
      const existing = groups.get(docKey);
      if (existing) {
        existing.push(item);
      } else {
        groups.set(docKey, [item]);
      }
    });

    const rows: TableRow[] = [];
    groups.forEach((groupItems, docName) => {
      rows.push({
        rowKey: `group-${docName}`,
        isGroupHeader: true,
        source_document: docName,
        count: groupItems.length,
      });

      groupItems.forEach((item, idx) => {
        rows.push({
          ...item,
          rowKey: `vuln-${item.id}`,
          isGroupHeader: false,
          groupIndex: idx + 1,
        });
      });
    });

    return rows;
  }, [items, documentFilter]);

  const handleQuickStatusChange = async (id: number, newStatus: string) => {
    try {
      const response = await apiClient.patch<VulnerabilityItem>(
        `/vulnerabilities/${id}`,
        { status: newStatus }
      );
      setItems((prev) =>
        prev.map((item) => (item.id === id ? response.data : item))
      );
      message.success(`Статус изменён: ${newStatus}`);
    } catch {
      message.error("Ошибка при обновлении статуса");
    }
  };

  const handleMarkNotRelevant = async (record: VulnerabilityItem) => {
    try {
      const response = await apiClient.patch<VulnerabilityItem>(
        `/vulnerabilities/${record.id}`,
        {
          status: "Выполнена",
          action_taken: NOT_RELEVANT_TEXT,
        }
      );
      setItems((prev) =>
        prev.map((item) => (item.id === record.id ? response.data : item))
      );
      message.success(`${record.bdu || "Запись"} помечена как не актуальная`);
    } catch {
      message.error("Ошибка при обновлении записи");
    }
  };

  const openEditModal = (record: VulnerabilityItem) => {
    setEditingItem(record);
    form.setFieldsValue({
      source_document: record.source_document ?? "",
      bdu: record.bdu ?? "",
      cve: record.cve ?? "",
      status: record.status,
      description: record.description,
      action_taken: record.action_taken,
    });
  };

  const handleSave = async () => {
    if (!editingItem) return;
    try {
      const values = await form.validateFields();
      setSaving(true);
      const response = await apiClient.patch<VulnerabilityItem>(
        `/vulnerabilities/${editingItem.id}`,
        {
          source_document: values.source_document || null,
          bdu: values.bdu || null,
          cve: values.cve || null,
          status: values.status,
          description: values.description,
          action_taken: values.action_taken,
        }
      );
      setItems((prev) =>
        prev.map((item) => (item.id === editingItem.id ? response.data : item))
      );
      message.success("Запись обновлена");
      setEditingItem(null);
    } catch {
      message.error("Ошибка при сохранении изменений");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await apiClient.delete(`/vulnerabilities/${id}`);
      setItems((prev) => prev.filter((item) => item.id !== id));
      message.success("Запись удалена");
    } catch {
      message.error("Не удалось удалить запись");
    }
  };

  const handleExport = async () => {
    try {
      const response = await apiClient.get("/vulnerabilities/export", {
        params: { only_ready: onlyReadyExport },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "fstec_report.csv");
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      message.error("Ошибка при экспорте отчёта");
    }
  };

  const hideIfGroupHeader = (record: TableRow) =>
    record.isGroupHeader ? { colSpan: 0 } : {};

  const columns: ColumnsType<TableRow> = [
    {
      title: "№ п/п",
      key: "index",
      width: 68,
      align: "center",
      onCell: (record) =>
        record.isGroupHeader
          ? {
              colSpan: TOTAL_COLUMNS,
              style: {
                textAlign: "left",
                background: "rgba(230, 25, 46, 0.08)",
                borderTop: "2px solid #e6192e",
                borderBottom: "1px solid rgba(230, 25, 46, 0.3)",
                padding: "9px 14px",
              },
            }
          : {},
      render: (_val, record) => {
        if (record.isGroupHeader) {
          return (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <Space size={10}>
                <FileTextOutlined style={{ color: "#e6192e", fontSize: 15 }} />
                <Text
                  strong
                  style={{
                    color: "#f0f2f5",
                    letterSpacing: "0.05em",
                    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
                  }}
                >
                  ПИСЬМО: {record.source_document}
                </Text>
              </Space>
              <Tag
                style={{
                  marginRight: 0,
                  background: "rgba(230, 25, 46, 0.14)",
                  borderColor: "#e6192e",
                  color: "#f0f2f5",
                }}
              >
                ЗАПИСЕЙ: {record.count}
              </Tag>
            </div>
          );
        }
        return <Text type="secondary">{record.groupIndex}</Text>;
      },
    },
    {
      title: "БДУ",
      key: "bdu",
      width: 155,
      onCell: hideIfGroupHeader,
      render: (_val, record) => {
        if (record.isGroupHeader) return null;
        return (
          <Tag
            style={{
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
              marginRight: 0,
              background: "rgba(255, 255, 255, 0.05)",
              borderColor: "#3a3e4d",
              color: "#f0f2f5",
            }}
          >
            {record.bdu || "—"}
          </Tag>
        );
      },
    },
    {
      title: "CVE",
      key: "cve",
      width: 185,
      onCell: hideIfGroupHeader,
      render: (_val, record) => {
        if (record.isGroupHeader) return null;
        if (!record.cve) return <Text type="secondary">—</Text>;
        const cveList = record.cve
          .split(",")
          .map((c) => c.trim())
          .filter(Boolean);
        return (
          <Space direction="vertical" size={4}>
            {cveList.map((cve) => (
              <Tag
                key={cve}
                style={{
                  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
                  marginRight: 0,
                  background: "rgba(230, 25, 46, 0.12)",
                  borderColor: "rgba(230, 25, 46, 0.5)",
                  color: "#ff6b78",
                }}
              >
                {cve}
              </Tag>
            ))}
          </Space>
        );
      },
    },
    {
      title: "Описание",
      key: "description",
      onCell: hideIfGroupHeader,
      render: (_val, record) => {
        if (record.isGroupHeader) return null;
        return (
          <div>
            <Paragraph
              ellipsis={{ rows: 3, expandable: true, symbol: "развернуть" }}
              style={{ marginBottom: 4 }}
            >
              {record.description || "—"}
            </Paragraph>
            {record.affected_software && (
              <Text type="secondary" style={{ fontSize: 12 }}>
                ПО: {record.affected_software}
              </Text>
            )}
          </div>
        );
      },
    },
    {
      title: "Что сделано",
      key: "action_taken",
      width: 240,
      onCell: hideIfGroupHeader,
      render: (_val, record) => {
        if (record.isGroupHeader) return null;
        if (!record.action_taken) {
          return <Text type="secondary">Не заполнено</Text>;
        }
        const markedNotRel = isNotRelevant(record.action_taken);
        return (
          <Space direction="vertical" size={4} style={{ width: "100%" }}>
            {markedNotRel && (
              <Tag
                icon={<StopOutlined />}
                style={{
                  marginRight: 0,
                  background: "rgba(107, 114, 128, 0.16)",
                  borderColor: "#6b7280",
                  color: "#c2c7d1",
                }}
              >
                Не актуально
              </Tag>
            )}
            <Paragraph
              ellipsis={{ rows: 3, expandable: true, symbol: "развернуть" }}
              style={{ marginBottom: 0 }}
            >
              {record.action_taken}
            </Paragraph>
          </Space>
        );
      },
    },
    {
      title: "Статус",
      key: "status",
      width: 155,
      onCell: hideIfGroupHeader,
      render: (_val, record) => {
        if (record.isGroupHeader) return null;
        return (
          <Select
            size="small"
            value={record.status}
            options={VULN_STATUSES}
            style={{ width: "100%" }}
            onChange={(val) => handleQuickStatusChange(record.id, val)}
          />
        );
      },
    },
    {
      title: "",
      key: "actions",
      width: 112,
      align: "right",
      onCell: hideIfGroupHeader,
      render: (_val, record) => {
        if (record.isGroupHeader) return null;
        const alreadyNotRel = isNotRelevant(record.action_taken);
        return (
          <Space size={2}>
            <Tooltip
              title={
                alreadyNotRel
                  ? "Отмечено как не актуальная"
                  : "Пометить как не актуальную"
              }
            >
              <Button
                type="text"
                size="small"
                icon={<StopOutlined />}
                style={{
                  color: alreadyNotRel ? "#e6192e" : "rgba(255, 255, 255, 0.5)",
                }}
                onClick={() => handleMarkNotRelevant(record)}
              />
            </Tooltip>
            <Tooltip title="Редактировать">
              <Button
                type="text"
                size="small"
                icon={<EditOutlined />}
                onClick={() => openEditModal(record)}
              />
            </Tooltip>
            <Popconfirm
              title="Удалить запись и связанные задачи?"
              onConfirm={() => handleDelete(record.id)}
              okText="Да"
              cancelText="Нет"
            >
              <Button type="text" size="small" danger icon={<DeleteOutlined />} />
            </Popconfirm>
          </Space>
        );
      },
    },
  ];

  return (
    <Card
      title="Реестр уязвимостей и отчётность"
      extra={
        <Space wrap>
          <Input
            placeholder="Поиск по БДУ, CVE, описанию..."
            prefix={<SearchOutlined />}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onPressEnter={fetchVulnerabilities}
            allowClear
            style={{ width: 230 }}
          />
          {uniqueDocuments.length > 1 && (
            <Select
              placeholder="Письмо"
              allowClear
              options={uniqueDocuments.map((doc) => ({ value: doc, label: doc }))}
              value={documentFilter}
              onChange={setDocumentFilter}
              style={{ width: 200 }}
            />
          )}
          <Select
            placeholder="Статус"
            allowClear
            options={VULN_STATUSES}
            value={statusFilter}
            onChange={setStatusFilter}
            style={{ width: 140 }}
          />
          <Button icon={<ReloadOutlined />} onClick={fetchVulnerabilities} loading={loading}>
            Обновить
          </Button>
          <Checkbox
            checked={onlyReadyExport}
            onChange={(e) => setOnlyReadyExport(e.target.checked)}
          >
            Только готовые
          </Checkbox>
          <Button type="primary" icon={<DownloadOutlined />} onClick={handleExport}>
            Экспорт CSV
          </Button>
        </Space>
      }
    >
      <Table
        rowKey="rowKey"
        size="middle"
        columns={columns}
        dataSource={tableRows}
        loading={loading}
        scroll={{ x: 980 }}
        pagination={{ pageSize: 50, showSizeChanger: true }}
        locale={{ emptyText: "Записи об уязвимостях не найдены" }}
      />

      <Modal
        title={`Редактирование записи #${editingItem?.id}`}
        open={Boolean(editingItem)}
        onOk={handleSave}
        onCancel={() => setEditingItem(null)}
        confirmLoading={saving}
        okText="Сохранить"
        cancelText="Отмена"
        width={640}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="source_document" label="Номер письма">
            <Input placeholder="Например, № 240/24/1234" />
          </Form.Item>
          <Space style={{ display: "flex" }} size="middle">
            <Form.Item name="bdu" label="БДУ" style={{ flex: 1 }}>
              <Input placeholder="BDU:2024-01234" />
            </Form.Item>
            <Form.Item name="cve" label="CVE" style={{ flex: 1 }}>
              <Input placeholder="CVE-2024-12345" />
            </Form.Item>
            <Form.Item name="status" label="Статус" rules={[{ required: true }]} style={{ flex: 1 }}>
              <Select options={VULN_STATUSES} />
            </Form.Item>
          </Space>
          <Form.Item name="description" label="Описание">
            <TextArea rows={4} />
          </Form.Item>
          <Form.Item
            name="action_taken"
            label={
              <Space style={{ width: "100%", justifyContent: "space-between" }}>
                <span>Что сделано</span>
                <Button
                  type="link"
                  size="small"
                  icon={<StopOutlined />}
                  style={{ padding: 0, color: "#e6192e" }}
                  onClick={() =>
                    form.setFieldsValue({
                      action_taken: NOT_RELEVANT_TEXT,
                      status: "Выполнена",
                    })
                  }
                >
                  Пометить «Не актуально»
                </Button>
              </Space>
            }
          >
            <TextArea rows={3} placeholder="Принятые меры по устранению..." />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
