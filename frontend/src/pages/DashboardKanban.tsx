import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Card,
  Col,
  Empty,
  Progress,
  Row,
  Segmented,
  Select,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from "antd";
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  FileTextOutlined,
  RadarChartOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
} from "@ant-design/icons";
import apiClient from "../api/client";

const { Text } = Typography;

interface BduStats {
  total: number;
  closed: number;
  in_progress: number;
  not_relevant: number;
  completion_percentage: number;
}

interface IocStats {
  total: number;
  done: number;
  in_progress: number;
  completion_percentage: number;
}

interface ProgressStats {
  overall_percentage: number;
  done_entities: number;
  total_entities: number;
  letters_total: number;
  letters_in_progress: number;
  letters_completed: number;
  letters_closed: number;
  letters_completion_percentage: number;
}

interface LetterCard {
  source_document: string;
  status: "В работе" | "Выполнено" | "Закрыто";
  categories: string[];
  bdu_total: number;
  bdu_closed: number;
  bdu_not_relevant: number;
  bdu_in_progress: number;
  ioc_total: number;
  ioc_done: number;
  ioc_in_progress: number;
  total_items: number;
  done_items: number;
  progress_percentage: number;
  updated_at: string | null;
}

interface DashboardState {
  bdu_stats: BduStats;
  ioc_stats: IocStats;
  progress: ProgressStats;
  letters: {
    in_progress: LetterCard[];
    completed_or_closed: LetterCard[];
  };
}

interface DonutSlice {
  key: string;
  label: string;
  value: number;
  color: string;
  percent: number;
}

const LETTER_STATUS_OPTIONS = [
  { value: "В работе", label: "В работе" },
  { value: "Выполнено", label: "Выполнено" },
  { value: "Закрыто", label: "Закрыто" },
];

const MONO_FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

function BduDonutChart({ stats }: { stats: BduStats }) {
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);

  const slices: DonutSlice[] = useMemo(() => {
    const total = stats.total || 0;
    const pct = (val: number) => (total > 0 ? Math.round((val / total) * 1000) / 10 : 0);
    return [
      {
        key: "closed",
        label: "Закрыты / Выполнены",
        value: stats.closed,
        color: "#10b981",
        percent: pct(stats.closed),
      },
      {
        key: "in_progress",
        label: "В работе",
        value: stats.in_progress,
        color: "#e6192e",
        percent: pct(stats.in_progress),
      },
      {
        key: "not_relevant",
        label: "Не актуальны",
        value: stats.not_relevant,
        color: "#6b7280",
        percent: pct(stats.not_relevant),
      },
    ];
  }, [stats]);

  const size = 196;
  const strokeWidth = 24;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  const activeSlice = slices.find((s) => s.key === hoveredKey) || null;
  let cumulativeOffset = 0;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 24,
        flexWrap: "wrap",
      }}
    >
      <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(255, 255, 255, 0.07)"
            strokeWidth={strokeWidth}
          />
          {stats.total > 0 &&
            slices.map((slice) => {
              if (slice.value <= 0) return null;
              const segLen = (slice.value / stats.total) * circumference;
              const gap = slices.filter((s) => s.value > 0).length > 1 ? 3 : 0;
              const dashLen = Math.max(0, segLen - gap);
              const dashOffset = -cumulativeOffset;
              cumulativeOffset += segLen;
              const isHovered = hoveredKey === slice.key;

              return (
                <circle
                  key={slice.key}
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="none"
                  stroke={slice.color}
                  strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                  strokeDasharray={`${dashLen} ${circumference - dashLen}`}
                  strokeDashoffset={dashOffset}
                  transform={`rotate(-90 ${size / 2} ${size / 2})`}
                  style={{
                    cursor: "pointer",
                    transition: "stroke-width 0.2s ease, opacity 0.2s ease",
                    opacity: hoveredKey && !isHovered ? 0.4 : 1,
                  }}
                  onMouseEnter={() => setHoveredKey(slice.key)}
                  onMouseLeave={() => setHoveredKey(null)}
                />
              );
            })}
        </svg>

        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            pointerEvents: "none",
            textAlign: "center",
            padding: "0 20px",
          }}
        >
          <span
            style={{
              fontSize: 30,
              fontWeight: 700,
              lineHeight: 1.1,
              fontFamily: MONO_FONT,
              color: activeSlice ? activeSlice.color : "#f0f2f5",
            }}
          >
            {activeSlice ? activeSlice.value : stats.total}
          </span>
          <Text type="secondary" style={{ fontSize: 11, letterSpacing: "0.08em", marginTop: 4 }}>
            {activeSlice ? `${activeSlice.percent}%` : "ВСЕГО БДУ"}
          </Text>
        </div>
      </div>

      <div style={{ flex: 1, minWidth: 220 }}>
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          {slices.map((slice) => {
            const isHovered = hoveredKey === slice.key;
            return (
              <div
                key={slice.key}
                onMouseEnter={() => setHoveredKey(slice.key)}
                onMouseLeave={() => setHoveredKey(null)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "10px 12px",
                  cursor: "pointer",
                  background: isHovered
                    ? "rgba(255, 255, 255, 0.06)"
                    : "rgba(255, 255, 255, 0.02)",
                  border: `1px solid ${
                    isHovered ? slice.color : "rgba(255, 255, 255, 0.08)"
                  }`,
                  borderLeft: `3px solid ${slice.color}`,
                  transition: "all 0.2s ease",
                }}
              >
                <Text style={{ fontSize: 13 }}>{slice.label}</Text>
                <Space size={10}>
                  <Text strong style={{ fontFamily: MONO_FONT, color: slice.color }}>
                    {slice.value}
                  </Text>
                  <Text
                    type="secondary"
                    style={{ fontFamily: MONO_FONT, fontSize: 12, minWidth: 44, textAlign: "right" }}
                  >
                    {slice.percent}%
                  </Text>
                </Space>
              </div>
            );
          })}
        </Space>
      </div>
    </div>
  );
}

export default function DashboardKanban() {
  const [data, setData] = useState<DashboardState | null>(null);
  const [loading, setLoading] = useState(true);
  const [doneFilter, setDoneFilter] = useState<string>("Все");
  const [updatingDoc, setUpdatingDoc] = useState<string | null>(null);

  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const response = await apiClient.get<DashboardState>("/kanban/dashboard");
      setData(response.data);
    } catch {
      message.error("Не удалось загрузить данные аналитики");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  const handleLetterStatusChange = async (sourceDocument: string, newStatus: string) => {
    setUpdatingDoc(sourceDocument);
    try {
      await apiClient.patch("/kanban/letters/status", {
        source_document: sourceDocument,
        status: newStatus,
      });
      message.success(`Письмо «${sourceDocument}»: статус → ${newStatus}`);
      await fetchDashboard();
    } catch {
      message.error("Не удалось обновить статус письма");
    } finally {
      setUpdatingDoc(null);
    }
  };

  const filteredCompletedLetters = useMemo(() => {
    const list = data?.letters.completed_or_closed ?? [];
    if (doneFilter === "Выполнено") {
      return list.filter((l) => l.status === "Выполнено");
    }
    if (doneFilter === "Закрыто") {
      return list.filter((l) => l.status === "Закрыто");
    }
    return list;
  }, [data, doneFilter]);

  const renderLetterCard = (letter: LetterCard) => {
    const isWorking = letter.status === "В работе";
    const statusColor =
      letter.status === "Закрыто"
        ? "success"
        : letter.status === "Выполнено"
          ? "default"
          : "error";

    return (
      <Card
        key={letter.source_document}
        size="small"
        style={{
          marginBottom: 12,
          borderTop: `2px solid ${isWorking ? "#e6192e" : "#10b981"}`,
        }}
        title={
          <Space size={8}>
            <FileTextOutlined style={{ color: isWorking ? "#e6192e" : "#10b981" }} />
            <Text
              strong
              style={{
                fontFamily: MONO_FONT,
                fontSize: 13,
                color: "#f0f2f5",
              }}
            >
              {letter.source_document}
            </Text>
          </Space>
        }
        extra={
          <Select
            size="small"
            value={letter.status}
            options={LETTER_STATUS_OPTIONS}
            loading={updatingDoc === letter.source_document}
            style={{ width: 125 }}
            onChange={(val) => handleLetterStatusChange(letter.source_document, val)}
          />
        }
      >
        <Space direction="vertical" size={8} style={{ width: "100%" }}>
          <Space wrap size={[6, 6]}>
            <Tag color={statusColor} style={{ marginRight: 0 }}>
              {letter.status}
            </Tag>
            {letter.bdu_total > 0 && (
              <Tag
                style={{
                  marginRight: 0,
                  fontFamily: MONO_FONT,
                  background: "rgba(255, 255, 255, 0.04)",
                  borderColor: "#3a3e4d",
                  color: "#e2e5ec",
                }}
              >
                БДУ: {letter.bdu_total}
              </Tag>
            )}
            {letter.ioc_total > 0 && (
              <Tag
                style={{
                  marginRight: 0,
                  fontFamily: MONO_FONT,
                  background: "rgba(230, 25, 46, 0.12)",
                  borderColor: "rgba(230, 25, 46, 0.55)",
                  color: "#ff5c6c",
                }}
              >
                IOC: {letter.ioc_total}
              </Tag>
            )}
            {letter.bdu_not_relevant > 0 && (
              <Tag
                icon={<StopOutlined />}
                style={{
                  marginRight: 0,
                  fontFamily: MONO_FONT,
                  background: "rgba(107, 114, 128, 0.16)",
                  borderColor: "#6b7280",
                  color: "#b4bac6",
                }}
              >
                Не акт.: {letter.bdu_not_relevant}
              </Tag>
            )}
          </Space>

          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <Progress
              percent={letter.progress_percentage}
              size="small"
              strokeColor={isWorking ? "#e6192e" : "#10b981"}
              trailColor="rgba(255, 255, 255, 0.07)"
              style={{ marginBottom: 0, flex: 1 }}
            />
            <Text type="secondary" style={{ fontSize: 12, fontFamily: MONO_FONT }}>
              {letter.done_items}/{letter.total_items}
            </Text>
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 8,
              paddingTop: 6,
              borderTop: "1px solid rgba(255, 255, 255, 0.06)",
              fontSize: 12,
            }}
          >
            <Space size={12} wrap>
              {letter.bdu_total > 0 && (
                <Text type="secondary">
                  БДУ отработано: {letter.bdu_closed + letter.bdu_not_relevant}/{letter.bdu_total}
                </Text>
              )}
              {letter.ioc_total > 0 && (
                <Text type="secondary">
                  IOC выгружено: {letter.ioc_done}/{letter.ioc_total}
                </Text>
              )}
            </Space>
          </div>
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

  const bduStats: BduStats = data?.bdu_stats ?? {
    total: 0,
    closed: 0,
    in_progress: 0,
    not_relevant: 0,
    completion_percentage: 0,
  };
  const iocStats: IocStats = data?.ioc_stats ?? {
    total: 0,
    done: 0,
    in_progress: 0,
    completion_percentage: 0,
  };
  const progress: ProgressStats = data?.progress ?? {
    overall_percentage: 0,
    done_entities: 0,
    total_entities: 0,
    letters_total: 0,
    letters_in_progress: 0,
    letters_completed: 0,
    letters_closed: 0,
    letters_completion_percentage: 0,
  };
  const inProgressLetters = data?.letters.in_progress ?? [];
  const doneLettersCount = data?.letters.completed_or_closed.length ?? 0;

  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Row gutter={[16, 16]} align="stretch">
        <Col xs={24} xl={14}>
          <Card
            style={{ height: "100%" }}
            title={
              <Space>
                <SafetyCertificateOutlined style={{ color: "#e6192e" }} />
                <span>Статистика по БДУ в реестре</span>
              </Space>
            }
            extra={
              <Tag
                style={{
                  marginRight: 0,
                  background: "rgba(230, 25, 46, 0.14)",
                  borderColor: "#e6192e",
                  color: "#f0f2f5",
                  fontFamily: MONO_FONT,
                }}
              >
                ОТРАБОТАНО: {Math.round(bduStats.completion_percentage)}%
              </Tag>
            }
          >
            <BduDonutChart stats={bduStats} />
          </Card>
        </Col>

        <Col xs={24} xl={10}>
          <Space direction="vertical" size={16} style={{ width: "100%", height: "100%" }}>
            <Card
              size="small"
              title={
                <Space>
                  <RadarChartOutlined style={{ color: "#e6192e" }} />
                  <span>Индикаторы компрометации (IOC)</span>
                </Space>
              }
              extra={
                <Text strong style={{ fontSize: 22, fontFamily: MONO_FONT, color: "#f0f2f5" }}>
                  {iocStats.total}
                </Text>
              }
            >
              <Space direction="vertical" size={8} style={{ width: "100%" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <Text type="secondary">
                    Отработано:{" "}
                    <Text strong style={{ color: "#10b981", fontFamily: MONO_FONT }}>
                      {iocStats.done}
                    </Text>
                  </Text>
                  <Text type="secondary">
                    В работе:{" "}
                    <Text strong style={{ color: "#e6192e", fontFamily: MONO_FONT }}>
                      {iocStats.in_progress}
                    </Text>
                  </Text>
                </div>
                <Progress
                  percent={Math.round(iocStats.completion_percentage)}
                  strokeColor="#e6192e"
                  trailColor="rgba(255, 255, 255, 0.07)"
                  size="small"
                  style={{ marginBottom: 0 }}
                />
              </Space>
            </Card>

            <Card
              size="small"
              style={{ flex: 1 }}
              title={
                <Space>
                  <CheckCircleOutlined style={{ color: "#10b981" }} />
                  <span>Общий прогресс отработки</span>
                </Space>
              }
              extra={
                <Text strong style={{ fontSize: 20, fontFamily: MONO_FONT, color: "#10b981" }}>
                  {Math.round(progress.overall_percentage)}%
                </Text>
              }
            >
              <Space direction="vertical" size={10} style={{ width: "100%" }}>
                <Progress
                  percent={Math.round(progress.overall_percentage)}
                  status={progress.overall_percentage < 100 ? "active" : "success"}
                  strokeColor={{ from: "#e6192e", to: "#10b981" }}
                  trailColor="rgba(255, 255, 255, 0.07)"
                  style={{ marginBottom: 0 }}
                />
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    flexWrap: "wrap",
                    gap: 8,
                    fontSize: 12,
                  }}
                >
                  <Text type="secondary">
                    Записей (БДУ + IOC):{" "}
                    <Text strong style={{ fontFamily: MONO_FONT, color: "#f0f2f5" }}>
                      {progress.done_entities}/{progress.total_entities}
                    </Text>
                  </Text>
                  <Text type="secondary">
                    Писем отработано:{" "}
                    <Text strong style={{ fontFamily: MONO_FONT, color: "#10b981" }}>
                      {progress.letters_completed + progress.letters_closed}/{progress.letters_total}
                    </Text>
                  </Text>
                </div>
              </Space>
            </Card>
          </Space>
        </Col>
      </Row>

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
        }}
      >
        <Space size={8} wrap>
          <Tag style={{ fontFamily: MONO_FONT }}>ВСЕГО ПИСЕМ: {progress.letters_total}</Tag>
          <Tag color="error" style={{ fontFamily: MONO_FONT }}>
            В РАБОТЕ: {progress.letters_in_progress}
          </Tag>
          <Tag
            style={{
              fontFamily: MONO_FONT,
              background: "rgba(255, 255, 255, 0.05)",
              borderColor: "#4b5060",
              color: "#f0f2f5",
            }}
          >
            ВЫПОЛНЕНО: {progress.letters_completed}
          </Tag>
          <Tag color="success" style={{ fontFamily: MONO_FONT }}>
            ЗАКРЫТО: {progress.letters_closed}
          </Tag>
        </Space>

        <Button icon={<ReloadOutlined />} onClick={fetchDashboard} loading={loading}>
          Обновить аналитику
        </Button>
      </div>

      <Row gutter={[16, 16]} align="top">
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <ClockCircleOutlined style={{ color: "#e6192e" }} />
                <span>Письма в работе ({inProgressLetters.length})</span>
              </Space>
            }
            styles={{
              header: {
                background: "rgba(230, 25, 46, 0.08)",
                borderBottom: "1px solid rgba(230, 25, 46, 0.3)",
              },
            }}
          >
            {inProgressLetters.length > 0 ? (
              inProgressLetters.map(renderLetterCard)
            ) : (
              <Empty description="Писем в работе нет" />
            )}
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <CheckCircleOutlined style={{ color: "#10b981" }} />
                <span>Выполненные и закрытые письма ({doneLettersCount})</span>
              </Space>
            }
            extra={
              <Segmented
                size="small"
                options={["Все", "Выполнено", "Закрыто"]}
                value={doneFilter}
                onChange={(val) => setDoneFilter(String(val))}
              />
            }
            styles={{
              header: {
                background: "rgba(16, 185, 129, 0.08)",
                borderBottom: "1px solid rgba(16, 185, 129, 0.3)",
              },
            }}
          >
            {filteredCompletedLetters.length > 0 ? (
              filteredCompletedLetters.map(renderLetterCard)
            ) : (
              <Empty description="Выполненных или закрытых писем пока нет" />
            )}
          </Card>
        </Col>
      </Row>
    </Space>
  );
}
