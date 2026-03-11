// src/rules/protected-paths.ts — Paths that should not be written/deleted (bilingual)

import type { ProtectedPathRule } from '../types'

export const PROTECTED_PATHS: ProtectedPathRule[] = [
  {
    id: 'env_file',
    pattern: /(?:^|\/)\.env(?:\.[a-zA-Z]+)?$/,
    description_zh: '环境变量文件（可能含密钥）',
    description_en: 'Environment file (may contain secrets)',
  },
  {
    id: 'ssh_dir',
    pattern: /(?:^|\/)\.ssh\//,
    description_zh: 'SSH 密钥目录',
    description_en: 'SSH key directory',
  },
  {
    id: 'gnupg_dir',
    pattern: /(?:^|\/)\.gnupg\//,
    description_zh: 'GPG 密钥目录',
    description_en: 'GPG key directory',
  },
  {
    id: 'aws_credentials',
    pattern: /(?:^|\/)\.aws\/credentials$/,
    description_zh: 'AWS 凭证文件',
    description_en: 'AWS credentials file',
  },
  {
    id: 'kube_config',
    pattern: /(?:^|\/)\.kube\/config$/,
    description_zh: 'Kubernetes 配置（含集群凭证）',
    description_en: 'Kubernetes config (contains cluster credentials)',
  },
  {
    id: 'docker_config',
    pattern: /(?:^|\/)\.docker\/config\.json$/,
    description_zh: 'Docker 配置（可能含 registry 凭证）',
    description_en: 'Docker config (may contain registry credentials)',
  },
  {
    id: 'git_credentials',
    pattern: /(?:^|\/)\.git-credentials$/,
    description_zh: 'Git 凭证文件',
    description_en: 'Git credentials file',
  },
  {
    id: 'npmrc',
    pattern: /(?:^|\/)\.npmrc$/,
    description_zh: 'npm 配置（可能含 registry token）',
    description_en: 'npm config (may contain registry token)',
  },
  {
    id: 'private_key',
    pattern: /(?:^|\/)(?:.*\.pem|.*\.key|.*_rsa|.*_ecdsa|.*_ed25519)$/,
    description_zh: '私钥文件',
    description_en: 'Private key file',
  },
  {
    id: 'etc_passwd',
    pattern: /^\/etc\/(?:passwd|shadow|sudoers)/,
    description_zh: '系统认证文件',
    description_en: 'System authentication file',
  },
  {
    id: 'keychain',
    pattern: /(?:^|\/)(?:Keychain|keychain|\.keystore|\.jks)$/,
    description_zh: '密钥链/密钥库文件',
    description_en: 'Keychain/keystore file',
  },
  {
    id: 'openclaw_config',
    pattern: /(?:^|\/)\.openclaw\/(?:config|settings|credentials)/,
    description_zh: 'OpenClaw 配置和凭证',
    description_en: 'OpenClaw config and credentials',
  },
]
