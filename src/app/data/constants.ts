export interface Pillar {
  key: string;
  label: string;
  shortLabel: string;
}

export const PILLARS: Pillar[] = [
  { key: "Identify", label: "식별자 및 신원", shortLabel: "신원" },
  { key: "Device", label: "기기 및 엔드포인트", shortLabel: "기기" },
  { key: "Network", label: "네트워크", shortLabel: "네트워크" },
  { key: "System", label: "시스템", shortLabel: "시스템" },
  { key: "Application", label: "애플리케이션 및 워크로드", shortLabel: "앱" },
  { key: "Data", label: "데이터", shortLabel: "데이터" },
];
