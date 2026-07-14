import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get, post, put, del } = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: {
    get,
    post,
    put,
    delete: del
  }
}))

import {
  createBackupJob,
  createS3Profile,
  createSourceProfile,
  deleteS3Profile,
  deleteSourceProfile,
  getAgentHealth,
  getBackupJob,
  getConfig,
  listBackupJobs,
  listS3Profiles,
  listSourceProfiles,
  setActiveS3Profile,
  setActiveSourceProfile,
  testS3,
  updateConfig,
  type BackupAgentHealth,
  type BackupJob,
  type DataManagementS3Profile,
  type DataManagementSourceProfile,
  type DeleteProfileResponse,
  type TestS3Response
} from '@/api/admin/dataManagement'

type Assert<T extends true> = T
type IsExact<T, U> = (
  (<G>() => G extends T ? 1 : 2) extends (<G>() => G extends U ? 1 : 2)
    ? (<G>() => G extends U ? 1 : 2) extends (<G>() => G extends T ? 1 : 2)
      ? true
      : false
    : false
)

type ExpectedAgentHealth = {
  healthy: boolean
  enabled: boolean
  mode: 'embedded_postgresql'
  message: string
}

type ExpectedBackupJob = {
  id: string
  status: 'running' | 'completed' | 'failed'
  backup_id: string
  created_at: string
  mode: 'embedded_postgresql'
}

type ExpectedDeleteResponse = { deleted: true }
type ExpectedTestS3Response = { ok: boolean; message: string; profile_id: string | null }

const agentHealthContract: Assert<IsExact<BackupAgentHealth, ExpectedAgentHealth>> = true
const backupJobContract: Assert<IsExact<BackupJob, ExpectedBackupJob>> = true
const deleteContract: Assert<IsExact<DeleteProfileResponse, ExpectedDeleteResponse>> = true
const testS3Contract: Assert<IsExact<TestS3Response, ExpectedTestS3Response>> = true

describe('admin data-management Rust API contract', () => {
  beforeEach(() => {
    get.mockReset()
    post.mockReset()
    put.mockReset()
    del.mockReset()
  })

  it('uses the embedded PostgreSQL health and config response shapes', async () => {
    const health: BackupAgentHealth = {
      healthy: true,
      enabled: false,
      mode: 'embedded_postgresql',
      message: 'backup and profile management are handled by the Rust process'
    }
    const config = { enabled: false, mode: 'embedded_postgresql' as const }
    get.mockResolvedValueOnce({ data: health }).mockResolvedValueOnce({ data: config })
    put.mockResolvedValueOnce({ data: config })

    await expect(getAgentHealth()).resolves.toEqual(health)
    await expect(getConfig()).resolves.toEqual(config)
    await expect(updateConfig(config)).resolves.toEqual(config)

    expect(get).toHaveBeenNthCalledWith(1, '/admin/data-management/agent/health')
    expect(get).toHaveBeenNthCalledWith(2, '/admin/data-management/config')
    expect(put).toHaveBeenCalledWith('/admin/data-management/config', config)
  })

  it('uses Rust profile ids and activation/delete result objects for PostgreSQL sources', async () => {
    const request = {
      profile_id: 'primary',
      name: 'Primary PostgreSQL',
      config: {
        host: 'postgres',
        port: 5432,
        user: 'sub2api',
        password: 'secret',
        database: 'sub2api',
        ssl_mode: 'disable',
        container_name: 'sub2api-postgres'
      },
      set_active: true
    }
    const profile: DataManagementSourceProfile = {
      ...request,
      id: 'runtime-id',
      active: false,
      created_at: '2026-07-14T00:00:00Z',
      config: { ...request.config, password: '********' }
    }
    const activated: DataManagementSourceProfile = { ...profile, active: true }
    const deleted: DeleteProfileResponse = { deleted: true }
    get.mockResolvedValue({ data: { items: [profile] } })
    post.mockResolvedValueOnce({ data: profile }).mockResolvedValueOnce({ data: activated })
    del.mockResolvedValue({ data: deleted })

    await expect(listSourceProfiles('postgres')).resolves.toEqual({ items: [profile] })
    await expect(createSourceProfile('postgres', request)).resolves.toEqual(profile)
    await expect(setActiveSourceProfile('postgres', 'runtime-id')).resolves.toEqual(activated)
    await expect(deleteSourceProfile('postgres', 'runtime-id')).resolves.toEqual(deleted)

    expect(post).toHaveBeenNthCalledWith(
      1,
      '/admin/data-management/sources/postgres/profiles',
      request
    )
    expect(post).toHaveBeenNthCalledWith(
      2,
      '/admin/data-management/sources/postgres/profiles/runtime-id/activate'
    )
    expect(del).toHaveBeenCalledWith(
      '/admin/data-management/sources/postgres/profiles/runtime-id'
    )
  })

  it('keeps Rust S3 profiles flat and returns activation/delete result objects', async () => {
    const request = {
      profile_id: 'archive',
      name: 'Archive',
      enabled: true,
      endpoint: 'https://s3.example.test',
      region: 'us-east-1',
      bucket: 'backups',
      access_key_id: 'access',
      secret_access_key: 'secret',
      prefix: 'sub2api',
      force_path_style: true,
      use_ssl: true,
      set_active: true
    }
    const profile: DataManagementS3Profile = {
      ...request,
      id: 'runtime-s3-id',
      active: false,
      created_at: '2026-07-14T00:00:00Z',
      secret_access_key: '********'
    }
    const activated: DataManagementS3Profile = { ...profile, active: true }
    const deleted: DeleteProfileResponse = { deleted: true }
    get.mockResolvedValue({ data: { items: [profile] } })
    post.mockResolvedValueOnce({ data: profile }).mockResolvedValueOnce({ data: activated })
    del.mockResolvedValue({ data: deleted })

    await expect(listS3Profiles()).resolves.toEqual({ items: [profile] })
    await expect(createS3Profile(request)).resolves.toEqual(profile)
    await expect(setActiveS3Profile('runtime-s3-id')).resolves.toEqual(activated)
    await expect(deleteS3Profile('runtime-s3-id')).resolves.toEqual(deleted)

    expect(post).toHaveBeenNthCalledWith(1, '/admin/data-management/s3/profiles', request)
    expect(post).toHaveBeenNthCalledWith(
      2,
      '/admin/data-management/s3/profiles/runtime-s3-id/activate'
    )
    expect(del).toHaveBeenCalledWith('/admin/data-management/s3/profiles/runtime-s3-id')
  })

  it('passes through the Rust S3 probe response including its nullable profile id', async () => {
    const request = {
      endpoint: 'minio:9000',
      region: 'us-east-1',
      bucket: 'backups',
      access_key_id: 'access',
      secret_access_key: 'secret',
      force_path_style: true,
      use_ssl: false
    }
    const response: TestS3Response = {
      ok: true,
      message: 'S3 connection and credentials verified',
      profile_id: null
    }
    post.mockResolvedValue({ data: response })

    await expect(testS3(request)).resolves.toEqual(response)
    expect(post).toHaveBeenCalledWith('/admin/data-management/s3/test', request)
  })

  it('uses the embedded backup job shape and does not promise unsupported filters or headers', async () => {
    const request = { backup_type: 'postgres' as const, expire_days: 7 }
    const job: BackupJob = {
      id: 'job-id',
      status: 'running',
      backup_id: 'job-id',
      created_at: '2026-07-14T00:00:00Z',
      mode: 'embedded_postgresql'
    }
    post.mockResolvedValue({ data: job })
    get.mockResolvedValueOnce({ data: { items: [job] } }).mockResolvedValueOnce({ data: job })

    await expect(createBackupJob(request)).resolves.toEqual(job)
    await expect(listBackupJobs()).resolves.toEqual({ items: [job] })
    await expect(getBackupJob('job-id')).resolves.toEqual(job)

    expect(post).toHaveBeenCalledWith('/admin/data-management/backups', request)
    expect(get).toHaveBeenNthCalledWith(1, '/admin/data-management/backups')
    expect(get).toHaveBeenNthCalledWith(2, '/admin/data-management/backups/job-id')
  })

  it('keeps the exported response contracts exact', () => {
    expect(agentHealthContract).toBe(true)
    expect(backupJobContract).toBe(true)
    expect(deleteContract).toBe(true)
    expect(testS3Contract).toBe(true)
  })
})
