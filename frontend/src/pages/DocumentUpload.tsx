import { useEffect, useRef, useState } from "react";
import {
  Card,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  Upload,
  message,
} from "antd";
import type { UploadProps } from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  InboxOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import apiClient from "../api/client";

const { Dragger } = Upload;
const { Title, Text } = Typography;

type DocType = "bdu" | "ioc" | "auto";

interface TaskResult {
  status?: string;
  doc_type?: DocType;
  filename?: string;
  source_document?: string;
  vulnerabilities_created?: number;
  iocs_created?: number;
  bdu_found?: string[];
}

interface UploadTaskItem {
  task_id: string;
  filename: string;
  doc_type: DocType;
  state: string;
  result?: TaskResult | null;
}

const ACCEPTED_EXTENSIONS = ".pdf,.docx,.doc,.rtf,.txt,.eml,.msg";

const DOC_TYPE_OPTIONS: { value: DocType; label: string }[] = [
  { value: "bdu", label: "Письмо БДУ (только уязвимости)" },
  { value: "ioc", label: "Письмо IOC (только индикаторы)" },
  { value: "auto", label: "Авто (БДУ + IOC)" },
];

const DOC_TYPE_HINTS: Record<DocType, string> = {
  bdu: "Парсер извлечёт номер письма, БДУ/CVE и описания. В реестр IOC ничего не добавится.",
  ioc: "Парсер извлечёт хэши, IP, домены и URL. Записи уязвимостей и задачи на канбане создаваться не будут.",
  auto: "Комбинированный режим: извлекает уязвимости БДУ и явные индикаторы компрометации.",
};

const DOC_TYPE_TAGS: Record<DocType, { label: string; color: string }> = {
  bdu: { label: "БДУ", color: "blue" },
  ioc: { label: "IOC", color: "volcano" },
  auto: { label: "АВТО", color: "cyan" },
};

export default function DocumentUpload() {
  const [docType, setDocType] = useState<DocType>("bdu");
  const [tasks, setTasks] = useState<UploadTaskItem[]>([]);
  const timersRef = useRef<Record<string, number>>({});

  useEffect(() => {
    return () => {
      Object.values(timersRef.current).forEach((timerId) => window.clearInterval(timerId));
    };
  }, []);

  const startPolling = (taskId: string) => {
    const timerId = window.setInterval(async () => {
      try {
        const res = await apiClient.get<{
          task_id: string;
          state: string;
          result: TaskResult | null;
        }>(`/documents/status/${taskId}`);

        const { state, result } = res.data;

        setTasks((prev) =>
          prev.map((item) =>
            item.task_id === taskId ? { ...item, state, result } : item
          )
        );

        if (state === "SUCCESS" || state === "FAILURE") {
          window.clearInterval(timersRef.current[taskId]);
          delete timersRef.current[taskId];

          if (state === "SUCCESS") {
            message.success(`Документ обработан (задача ${taskId.slice(0, 8)})`);
          } else {
            message.error(`Ошибка обработки документа (задача ${taskId.slice(0, 8)})`);
          }
        }
      } catch {
        window.clearInterval(timersRef.current[taskId]);
        delete timersRef.current[taskId];
      }
    }, 2500);

    timersRef.current[taskId] = timerId;
  };

  const uploadProps: UploadProps = {
    name: "file",
    multiple: true,
    accept: ACCEPTED_EXTENSIONS,
    showUploadList: false,
    customRequest: async ({ file, onSuccess, onError }) => {
      const selectedType = docType;
      const formData = new FormData();
      formData.append("file", file as Blob);
      formData.append("doc_type", selectedType);

      try {
        const response = await apiClient.post<{
          status: string;
          task_id: string;
          filename: string;
          doc_type?: DocType;
        }>("/documents/upload", formData, {
          headers: { "Content-Type": "multipart/form-data" },
        });

        const { task_id, filename } = response.data;
        setTasks((prev) => [
          {
            task_id,
            filename,
            doc_type: response.data.doc_type || selectedType,
            state: "PENDING",
            result: null,
          },
          ...prev,
        ]);
        startPolling(task_id);
        onSuccess?.(response.data);
      } catch (err) {
        message.error("Не удалось загрузить файл");
        onError?.(err as Error);
      }
    },
  };

  const renderStateTag = (state: string) => {
    switch (state) {
      case "SUCCESS":
        return (
          <Tag icon={<CheckCircleOutlined />} color="success">
            Готово
          </Tag>
        );
      case "FAILURE":
        return (
          <Tag icon={<CloseCircleOutlined />} color="error">
            Ошибка
          </Tag>
        );
      case "STARTED":
        return (
          <Tag icon={<SyncOutlined spin />} color="processing">
            Распознавание / OCR
          </Tag>
        );
      default:
        return (
          <Tag icon={<ClockCircleOutlined />} color="default">
            В очереди
          </Tag>
        );
    }
  };

  const columns: ColumnsType<UploadTaskItem> = [
    {
      title: "Файл",
      dataIndex: "filename",
      key: "filename",
      render: (name: string) => <Text strong>{name}</Text>,
    },
    {
      title: "Режим",
      dataIndex: "doc_type",
      key: "doc_type",
      width: 96,
      render: (type: DocType) => {
        const meta = DOC_TYPE_TAGS[type] || DOC_TYPE_TAGS.auto;
        return <Tag color={meta.color}>{meta.label}</Tag>;
      },
    },
    {
      title: "Статус",
      dataIndex: "state",
      key: "state",
      width: 190,
      render: renderStateTag,
    },
    {
      title: "Номер документа",
      key: "source_document",
      render: (_, record) => record.result?.source_document || "—",
    },
    {
      title: "Создано записей",
      key: "created",
      width: 230,
      render: (_, record) => {
        if (record.state !== "SUCCESS" || !record.result) return "—";
        return (
          <Space>
            <Tag color="blue">Уязвимостей: {record.result.vulnerabilities_created ?? 0}</Tag>
            <Tag color="volcano">IOC: {record.result.iocs_created ?? 0}</Tag>
          </Space>
        );
      },
    },
    {
      title: "Найденные БДУ",
      key: "bdu_found",
      render: (_, record) => {
        const list = record.result?.bdu_found;
        if (!list || list.length === 0) return "—";
        return (
          <Space wrap size={[4, 4]}>
            {list.map((bdu) => (
              <Tag key={bdu} color="geekblue">
                {bdu}
              </Tag>
            ))}
          </Space>
        );
      },
    },
  ];

  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Card>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 16,
            marginBottom: 16,
          }}
        >
          <div>
            <Title level={4} style={{ margin: 0 }}>
              Загрузка бюллетеней и писем
            </Title>
            <Text type="secondary" style={{ fontSize: 12.5 }}>
              {DOC_TYPE_HINTS[docType]}
            </Text>
          </div>

          <Space>
            <Text strong style={{ textTransform: "uppercase", fontSize: 12 }}>
              Тип письма:
            </Text>
            <Select<DocType>
              value={docType}
              onChange={(val) => setDocType(val)}
              options={DOC_TYPE_OPTIONS}
              style={{ width: 280 }}
            />
          </Space>
        </div>

        <Dragger {...uploadProps}>
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">
            Перетащите файлы сюда или нажмите для выбора
          </p>
          <p className="ant-upload-hint">
            Поддерживаются PDF (включая сканы с OCR), DOCX, DOC, RTF, TXT, EML и MSG.
          </p>
        </Dragger>
      </Card>

      <Card title="Очередь обработки">
        <Table
          rowKey="task_id"
          columns={columns}
          dataSource={tasks}
          pagination={false}
          locale={{ emptyText: "Загруженные документы появятся здесь" }}
        />
      </Card>
    </Space>
  );
}
