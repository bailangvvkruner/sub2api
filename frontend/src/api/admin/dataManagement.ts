import { apiClient } from '../client'

export type BackupType = 'postgres'
export type BackupJobStatus = 'running' | 'completed' | 'failed'
export type DataManagementMode = 'embedded_postgresql'

export interface BackupAgentHealth {
  healthy: boolean
  enabled: boolean
  mode: DataManagementMode
  message: string
}

export interface DataManagementS3Config {
  enabled: boolean
  endpoint: string
  region: string
  bucket: string
  access_key_id: string
  secret_access_key?: string
  secret_access_key_configured?: boolean
  prefix: string
  force_path_style: boolean
  use_ssl: boolean
}

export interface DataManagementConfig {
  enabled?: boolean
  mode?: DataManagementMode
  [key: string]: unknown
}

export type SourceType = 'postgres'

export interface DataManagementSourceConfig {
  host: string
  port: number
  user: string
  password?: string
  database: string
  ssl_mode: string
  container_name: string
}

export interface DataManagementProfileState {
  id: string
  active: boolean
  created_at: string
  updated_at?: string
}

export interface TestS3Request {
  endpoint: string
  region: string
  bucket: string
  access_key_id: string
  secret_access_key: string
  prefix?: string
  force_path_style?: boolean
  use_ssl?: boolean
}

export interface TestS3Response {
  ok: boolean
  message: string
  profile_id: string | null
}

export interface CreateBackupJobRequest {
  backup_type: BackupType
  expire_days?: number
}

export interface BackupJob {
  id: string
  status: BackupJobStatus
  backup_id: string
  created_at: string
  mode: DataManagementMode
}

export type CreateBackupJobResponse = BackupJob

export interface ListSourceProfilesResponse {
  items: DataManagementSourceProfile[]
}

export interface CreateSourceProfileRequest {
  profile_id: string
  name: string
  config: DataManagementSourceConfig
  set_active?: boolean
}

export interface UpdateSourceProfileRequest {
  name: string
  config: DataManagementSourceConfig
}

export interface DataManagementSourceProfile extends DataManagementProfileState {
  profile_id: string
  name: string
  config: DataManagementSourceConfig
  set_active?: boolean
}

export interface DataManagementS3Profile extends DataManagementProfileState {
  profile_id: string
  name: string
  enabled: boolean
  endpoint: string
  region: string
  bucket: string
  access_key_id: string
  secret_access_key?: string
  prefix?: string
  force_path_style?: boolean
  use_ssl?: boolean
  set_active?: boolean
}

export interface ListS3ProfilesResponse {
  items: DataManagementS3Profile[]
}

export interface CreateS3ProfileRequest {
  profile_id: string
  name: string
  enabled: boolean
  endpoint: string
  region: string
  bucket: string
  access_key_id: string
  secret_access_key?: string
  prefix?: string
  force_path_style?: boolean
  use_ssl?: boolean
  set_active?: boolean
}

export interface UpdateS3ProfileRequest {
  name: string
  enabled: boolean
  endpoint: string
  region: string
  bucket: string
  access_key_id: string
  secret_access_key?: string
  prefix?: string
  force_path_style?: boolean
  use_ssl?: boolean
}

export interface DeleteProfileResponse {
  deleted: true
}

export interface ListBackupJobsResponse {
  items: BackupJob[]
}

export async function getAgentHealth(): Promise<BackupAgentHealth> {
  const { data } = await apiClient.get<BackupAgentHealth>('/admin/data-management/agent/health')
  return data
}

export async function getConfig(): Promise<DataManagementConfig> {
  const { data } = await apiClient.get<DataManagementConfig>('/admin/data-management/config')
  return data
}

export async function updateConfig(request: DataManagementConfig): Promise<DataManagementConfig> {
  const { data } = await apiClient.put<DataManagementConfig>('/admin/data-management/config', request)
  return data
}

export async function testS3(request: TestS3Request): Promise<TestS3Response> {
  const { data } = await apiClient.post<TestS3Response>('/admin/data-management/s3/test', request)
  return data
}

export async function listSourceProfiles(sourceType: SourceType): Promise<ListSourceProfilesResponse> {
  const { data } = await apiClient.get<ListSourceProfilesResponse>(`/admin/data-management/sources/${sourceType}/profiles`)
  return data
}

export async function createSourceProfile(sourceType: SourceType, request: CreateSourceProfileRequest): Promise<DataManagementSourceProfile> {
  const { data } = await apiClient.post<DataManagementSourceProfile>(`/admin/data-management/sources/${sourceType}/profiles`, request)
  return data
}

export async function updateSourceProfile(sourceType: SourceType, profileID: string, request: UpdateSourceProfileRequest): Promise<DataManagementSourceProfile> {
  const { data } = await apiClient.put<DataManagementSourceProfile>(`/admin/data-management/sources/${sourceType}/profiles/${profileID}`, request)
  return data
}

export async function deleteSourceProfile(
  sourceType: SourceType,
  profileID: string
): Promise<DeleteProfileResponse> {
  const { data } = await apiClient.delete<DeleteProfileResponse>(
    `/admin/data-management/sources/${sourceType}/profiles/${profileID}`
  )
  return data
}

export async function setActiveSourceProfile(
  sourceType: SourceType,
  profileID: string
): Promise<DataManagementSourceProfile> {
  const { data } = await apiClient.post<DataManagementSourceProfile>(
    `/admin/data-management/sources/${sourceType}/profiles/${profileID}/activate`
  )
  return data
}

export async function listS3Profiles(): Promise<ListS3ProfilesResponse> {
  const { data } = await apiClient.get<ListS3ProfilesResponse>('/admin/data-management/s3/profiles')
  return data
}

export async function createS3Profile(request: CreateS3ProfileRequest): Promise<DataManagementS3Profile> {
  const { data } = await apiClient.post<DataManagementS3Profile>('/admin/data-management/s3/profiles', request)
  return data
}

export async function updateS3Profile(profileID: string, request: UpdateS3ProfileRequest): Promise<DataManagementS3Profile> {
  const { data } = await apiClient.put<DataManagementS3Profile>(`/admin/data-management/s3/profiles/${profileID}`, request)
  return data
}

export async function deleteS3Profile(profileID: string): Promise<DeleteProfileResponse> {
  const { data } = await apiClient.delete<DeleteProfileResponse>(
    `/admin/data-management/s3/profiles/${profileID}`
  )
  return data
}

export async function setActiveS3Profile(profileID: string): Promise<DataManagementS3Profile> {
  const { data } = await apiClient.post<DataManagementS3Profile>(
    `/admin/data-management/s3/profiles/${profileID}/activate`
  )
  return data
}

export async function createBackupJob(request: CreateBackupJobRequest): Promise<CreateBackupJobResponse> {
  const { data } = await apiClient.post<CreateBackupJobResponse>(
    '/admin/data-management/backups',
    request
  )
  return data
}

export async function listBackupJobs(): Promise<ListBackupJobsResponse> {
  const { data } = await apiClient.get<ListBackupJobsResponse>('/admin/data-management/backups')
  return data
}

export async function getBackupJob(jobID: string): Promise<BackupJob> {
  const { data } = await apiClient.get<BackupJob>(`/admin/data-management/backups/${jobID}`)
  return data
}

export const dataManagementAPI = {
  getAgentHealth,
  getConfig,
  updateConfig,
  listSourceProfiles,
  createSourceProfile,
  updateSourceProfile,
  deleteSourceProfile,
  setActiveSourceProfile,
  testS3,
  listS3Profiles,
  createS3Profile,
  updateS3Profile,
  deleteS3Profile,
  setActiveS3Profile,
  createBackupJob,
  listBackupJobs,
  getBackupJob
}

export default dataManagementAPI
