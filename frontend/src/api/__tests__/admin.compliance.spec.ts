import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get, post } = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: { get, post }
}))

import {
  adminComplianceAPI,
  type AcceptAdminComplianceRequest,
  type AdminComplianceStatus
} from '@/api/admin/compliance'

describe('admin compliance Rust API contract', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
  })

  it('loads the versioned per-admin acknowledgement status', async () => {
    const status: AdminComplianceStatus = {
      required: false,
      version: 'v2026.06.10',
      document_path_zh: 'docs/legal/admin-compliance.zh.md',
      document_path_en: 'docs/legal/admin-compliance.en.md',
      document_url_zh: 'https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.zh.md',
      document_url_en: 'https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.en.md',
      ack_phrase_zh: '我已阅读、理解并同意 Sub2API 部署与运营合规承诺',
      ack_phrase_en: 'I have read, understood, and agree to the Sub2API Deployment and Operation Compliance Commitment',
      acknowledgement: {
        version: 'v2026.06.10',
        document_zh: 'docs/legal/admin-compliance.zh.md',
        document_en: 'docs/legal/admin-compliance.en.md',
        admin_user_id: 42,
        accepted_at: '2026-07-14T00:00:00Z'
      }
    }
    get.mockResolvedValue({ data: status })

    await expect(adminComplianceAPI.getStatus()).resolves.toEqual(status)
    expect(get).toHaveBeenCalledWith('/admin/compliance')
  })

  it('sends the exact phrase and normalized frontend language', async () => {
    const request: AcceptAdminComplianceRequest = {
      phrase: 'I have read, understood, and agree to the Sub2API Deployment and Operation Compliance Commitment',
      language: 'en'
    }
    const status = {
      required: false,
      version: 'v2026.06.10'
    } as AdminComplianceStatus
    post.mockResolvedValue({ data: status })

    await expect(adminComplianceAPI.accept(request)).resolves.toEqual(status)
    expect(post).toHaveBeenCalledWith('/admin/compliance/accept', request)
  })
})
