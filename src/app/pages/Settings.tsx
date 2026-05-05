import { useState } from "react";
import { Settings as SettingsIcon, Bell, Target, User, Save } from "lucide-react";
import { toast } from "sonner";
import { PILLARS } from "../data/constants";

export function Settings() {
  const [targetScores, setTargetScores] = useState(PILLARS.map(() => 3.5));
  const [settings, setSettings] = useState({
    wazuhThreshold: 75,
    trivyCritical: true,
    trivyHigh: true,
    trivyMedium: false,
    coverageThreshold: 90,
    completeNotification: true,
    errorNotification: true,
    name: "관리자",
    email: "admin@example.com",
    organization: "보안팀",
  });

  const handleSave = () => {
    toast.success("설정이 저장되었습니다.");
  };

  const updateTarget = (index: number, value: number) => {
    setTargetScores((prev) => prev.map((score, i) => (i === index ? value : score)));
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <h1>설정</h1>

      {/* Threshold Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <SettingsIcon className="text-blue-600" size={20} />
          <h2>판정 임계값 설정</h2>
        </div>

        <div className="space-y-6">
          <div>
            <label className="block mb-2">Wazuh SCA 점수 기준값 (%)</label>
            <div className="flex items-center gap-4">
              <input
                type="range"
                min="0"
                max="100"
                value={settings.wazuhThreshold}
                onChange={(e) =>
                  setSettings({ ...settings, wazuhThreshold: parseInt(e.target.value) })
                }
                className="flex-1"
              />
              <span className="text-lg font-semibold text-blue-600 w-16 text-center">
                {settings.wazuhThreshold}%
              </span>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              이 값 이상일 때 해당 항목을 통과로 판정합니다
            </p>
          </div>

          <div>
            <label className="block mb-3">Trivy CVE Severity 기준</label>
            <div className="space-y-2">
              <label className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.trivyCritical}
                  onChange={(e) =>
                    setSettings({ ...settings, trivyCritical: e.target.checked })
                  }
                  className="w-4 h-4"
                />
                <span className="flex-1">Critical</span>
                <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-sm">위험</span>
              </label>
              <label className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.trivyHigh}
                  onChange={(e) =>
                    setSettings({ ...settings, trivyHigh: e.target.checked })
                  }
                  className="w-4 h-4"
                />
                <span className="flex-1">High</span>
                <span className="px-2 py-1 bg-orange-100 text-orange-700 rounded text-sm">높음</span>
              </label>
              <label className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.trivyMedium}
                  onChange={(e) =>
                    setSettings({ ...settings, trivyMedium: e.target.checked })
                  }
                  className="w-4 h-4"
                />
                <span className="flex-1">Medium</span>
                <span className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded text-sm">보통</span>
              </label>
            </div>
          </div>

          <div>
            <label className="block mb-2">커버리지 비율 기준값 (%)</label>
            <div className="flex items-center gap-4">
              <input
                type="range"
                min="50"
                max="100"
                value={settings.coverageThreshold}
                onChange={(e) =>
                  setSettings({ ...settings, coverageThreshold: parseInt(e.target.value) })
                }
                className="flex-1"
              />
              <span className="text-lg font-semibold text-blue-600 w-16 text-center">
                {settings.coverageThreshold}%
              </span>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              전체 항목 중 이 비율 이상 확인되어야 진단이 유효합니다
            </p>
          </div>
        </div>
      </div>

      {/* Target Maturity Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <Target className="text-emerald-600" size={20} />
          <h2>목표 성숙도 설정</h2>
        </div>

        <div className="space-y-4">
          {PILLARS.map((pillar, index) => (
            <div key={pillar.key}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium text-gray-700">{pillar.label}</span>
                <span className="text-sm font-semibold text-emerald-600">{targetScores[index].toFixed(1)} / 4.0</span>
              </div>
              <input
                type="range"
                min="0.5"
                max="4"
                step="0.1"
                value={targetScores[index]}
                onChange={(event) => updateTarget(index, Number(event.target.value))}
                className="w-full accent-emerald-600"
              />
              <div className="flex justify-between text-[11px] text-gray-400">
                <span>0.5</span>
                <span>4.0</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Notification Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <Bell className="text-blue-600" size={20} />
          <h2>알림 설정</h2>
        </div>

        <div className="space-y-3">
          <label className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
            <div>
              <h3>진단 완료 알림</h3>
              <p className="text-sm text-gray-600">진단이 완료되면 알림을 받습니다</p>
            </div>
            <input
              type="checkbox"
              checked={settings.completeNotification}
              onChange={(e) =>
                setSettings({ ...settings, completeNotification: e.target.checked })
              }
              className="w-5 h-5"
            />
          </label>
          <label className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
            <div>
              <h3>오류 발생 시 알림</h3>
              <p className="text-sm text-gray-600">진단 중 오류가 발생하면 즉시 알림을 받습니다</p>
            </div>
            <input
              type="checkbox"
              checked={settings.errorNotification}
              onChange={(e) =>
                setSettings({ ...settings, errorNotification: e.target.checked })
              }
              className="w-5 h-5"
            />
          </label>
        </div>
      </div>

      {/* User Account Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <User className="text-blue-600" size={20} />
          <h2>사용자 계정 정보</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block mb-2">이름</label>
            <input
              type="text"
              value={settings.name}
              onChange={(e) => setSettings({ ...settings, name: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg"
            />
          </div>
          <div>
            <label className="block mb-2">이메일</label>
            <input
              type="email"
              value={settings.email}
              onChange={(e) => setSettings({ ...settings, email: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg"
            />
          </div>
          <div>
            <label className="block mb-2">소속</label>
            <input
              type="text"
              value={settings.organization}
              onChange={(e) => setSettings({ ...settings, organization: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg"
            />
          </div>
          <div>
            <label className="block mb-2">비밀번호 변경</label>
            <button className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
              비밀번호 변경하기
            </button>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Save size={20} />
          설정 저장
        </button>
      </div>
    </div>
  );
}
