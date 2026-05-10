-- ZT Assessment DB 초기화 스크립트
-- CHARACTER SET utf8mb4 / COLLATE utf8mb4_unicode_ci

CREATE DATABASE IF NOT EXISTS zt_assessment
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE zt_assessment;

-- 1. Organization
CREATE TABLE IF NOT EXISTS Organization (
  org_id     INT          NOT NULL AUTO_INCREMENT,
  name       VARCHAR(200) NOT NULL,
  industry   VARCHAR(50)  NULL,
  size       VARCHAR(20)  NULL,
  cloud_type VARCHAR(30)  NULL,
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (org_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 2. User
CREATE TABLE IF NOT EXISTS User (
  user_id    INT          NOT NULL AUTO_INCREMENT,
  org_id     INT          NOT NULL,
  name       VARCHAR(100) NOT NULL,
  email      VARCHAR(200) NOT NULL,
  role       VARCHAR(50)  NOT NULL DEFAULT 'analyst',
  mfa_enabled TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  UNIQUE KEY uq_user_email (email),
  CONSTRAINT fk_user_org FOREIGN KEY (org_id) REFERENCES Organization (org_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 3. DiagnosisSession
CREATE TABLE IF NOT EXISTS DiagnosisSession (
  session_id   INT          NOT NULL AUTO_INCREMENT,
  org_id       INT          NOT NULL,
  user_id      INT          NOT NULL,
  status       ENUM('진행 중','완료','오류') NOT NULL DEFAULT '진행 중',
  level        VARCHAR(20)  NULL,
  total_score  FLOAT        NULL,
  started_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME     NULL,
  PRIMARY KEY (session_id),
  CONSTRAINT fk_session_org  FOREIGN KEY (org_id)  REFERENCES Organization (org_id),
  CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES User (user_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. Checklist
CREATE TABLE IF NOT EXISTS Checklist (
  check_id       INT          NOT NULL AUTO_INCREMENT,
  item_id        VARCHAR(20)  NOT NULL,
  pillar         VARCHAR(100) NOT NULL,
  category       VARCHAR(100) NOT NULL,
  item_name      VARCHAR(200) NOT NULL,
  maturity       VARCHAR(20)  NOT NULL,
  maturity_score INT          NOT NULL DEFAULT 0,
  question       TEXT         NOT NULL,
  diagnosis_type VARCHAR(20)  NOT NULL,
  tool           VARCHAR(100) NOT NULL,
  evidence       TEXT         NULL,
  criteria       TEXT         NULL,
  fields         TEXT         NULL,
  logic          TEXT         NULL,
  exceptions     TEXT         NULL,
  PRIMARY KEY (check_id),
  UNIQUE KEY uq_checklist_item_id (item_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. CollectedData  (인덱스: session_id, check_id)
CREATE TABLE IF NOT EXISTS CollectedData (
  data_id      INT          NOT NULL AUTO_INCREMENT,
  session_id   INT          NOT NULL,
  check_id     INT          NOT NULL,
  tool         VARCHAR(100) NOT NULL,
  metric_key   VARCHAR(200) NOT NULL,
  metric_value FLOAT        NULL,
  threshold    FLOAT        NULL,
  raw_json     JSON         NULL,
  collected_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  error        TEXT         NULL,
  PRIMARY KEY (data_id),
  INDEX idx_collected_data_session (session_id),
  INDEX idx_collected_data_check   (check_id),
  CONSTRAINT fk_collected_session   FOREIGN KEY (session_id) REFERENCES DiagnosisSession (session_id),
  CONSTRAINT fk_collected_checklist FOREIGN KEY (check_id)   REFERENCES Checklist (check_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. Evidence
CREATE TABLE IF NOT EXISTS Evidence (
  evidence_id INT          NOT NULL AUTO_INCREMENT,
  session_id  INT          NOT NULL,
  check_id    INT          NOT NULL,
  source      VARCHAR(200) NULL,
  observed    TEXT         NULL,
  location    VARCHAR(500) NULL,
  reason      TEXT         NULL,
  impact      FLOAT        NULL,
  PRIMARY KEY (evidence_id),
  CONSTRAINT fk_evidence_session   FOREIGN KEY (session_id) REFERENCES DiagnosisSession (session_id),
  CONSTRAINT fk_evidence_checklist FOREIGN KEY (check_id)   REFERENCES Checklist (check_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 7. DiagnosisResult
CREATE TABLE IF NOT EXISTS DiagnosisResult (
  result_id      INT  NOT NULL AUTO_INCREMENT,
  session_id     INT  NOT NULL,
  check_id       INT  NOT NULL,
  result         ENUM('충족','부분충족','미충족','평가불가') NOT NULL,
  score          FLOAT NULL,
  recommendation TEXT  NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (result_id),
  CONSTRAINT fk_result_session   FOREIGN KEY (session_id) REFERENCES DiagnosisSession (session_id),
  CONSTRAINT fk_result_checklist FOREIGN KEY (check_id)   REFERENCES Checklist (check_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 8. MaturityScore
CREATE TABLE IF NOT EXISTS MaturityScore (
  score_id   INT          NOT NULL AUTO_INCREMENT,
  session_id INT          NOT NULL,
  pillar     VARCHAR(100) NOT NULL,
  score      FLOAT        NOT NULL,
  level      VARCHAR(10)  NOT NULL DEFAULT '기존',
  pass_cnt   INT(11)      NOT NULL DEFAULT 0,
  fail_cnt   INT(11)      NOT NULL DEFAULT 0,
  na_cnt     INT(11)      NOT NULL DEFAULT 0,
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (score_id),
  CONSTRAINT fk_maturity_session FOREIGN KEY (session_id) REFERENCES DiagnosisSession (session_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 9. ImprovementGuide
CREATE TABLE IF NOT EXISTS ImprovementGuide (
  guide_id        INT          NOT NULL AUTO_INCREMENT,
  check_id        INT          NULL,
  current_level    VARCHAR(10)  NULL,
  next_level       VARCHAR(10)  NULL,
  recommended_tool VARCHAR(100) NULL,
  pillar          VARCHAR(100) NOT NULL,
  task            TEXT         NOT NULL,
  priority        ENUM('Critical','High','Medium','Low') NOT NULL,
  term            ENUM('단기','중기','장기') NOT NULL,
  duration        VARCHAR(100) NULL,
  difficulty      VARCHAR(50)  NULL,
  owner           VARCHAR(100) NULL,
  expected_gain   TEXT         NULL,
  related_item    VARCHAR(200) NULL,
  steps           JSON         NULL,
  expected_effect TEXT         NULL,
  PRIMARY KEY (guide_id),
  CONSTRAINT fk_guide_checklist FOREIGN KEY (check_id) REFERENCES Checklist (check_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 10. ScoreHistory  (인덱스: assessed_at)
CREATE TABLE IF NOT EXISTS ScoreHistory (
  history_id     INT         NOT NULL AUTO_INCREMENT,
  session_id     INT         NOT NULL,
  org_id         INT         NOT NULL,
  pillar_scores  JSON        NULL,
  total_score    FLOAT       NOT NULL,
  maturity_level VARCHAR(20) NOT NULL,
  assessed_at    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (history_id),
  INDEX idx_score_history_assessed_at (assessed_at),
  CONSTRAINT fk_history_session FOREIGN KEY (session_id) REFERENCES DiagnosisSession (session_id),
  CONSTRAINT fk_history_org     FOREIGN KEY (org_id)     REFERENCES Organization (org_id)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
