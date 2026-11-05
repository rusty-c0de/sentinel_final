import { sqliteTable, text, real, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core';
export const installations = sqliteTable('installations', {
 id:text('id').primaryKey(), name:text('name').notNull(), region:text('region').notNull(),
 lat:real('lat').notNull(), lng:real('lng').notNull(),
 contactName:text('contact_name').notNull(), contactEmail:text('contact_email').notNull(), contactPhone:text('contact_phone').notNull(),
 createdAt:text('created_at').notNull(), updatedAt:text('updated_at').notNull(),
});
export const incidents = sqliteTable('incidents', {
 id:text('id').primaryKey(), siteId:text('site_id').notNull().references(()=>installations.id,{onDelete:'cascade'}),
 title:text('title').notNull(), summary:text('summary').notNull(), severity:text('severity').notNull(), status:text('status').notNull(),
 logHash:text('log_hash'),logKey:text('log_key'), fileName:text('file_name'), attackMetadata:text('attack_metadata'),createdAt:text('created_at').notNull(),updatedAt:text('updated_at').notNull(),
},t=>[index('incidents_site_idx').on(t.siteId),uniqueIndex('incident_log_hash_idx').on(t.siteId,t.logHash)]);
export const sessions = sqliteTable('sessions',{
 tokenHash:text('token_hash').primaryKey(),expiresAt:integer('expires_at').notNull(),
});
export const loginLimits = sqliteTable('login_limits',{
 key:text('key').primaryKey(),attempts:integer('attempts').notNull(),expiresAt:integer('expires_at').notNull(),
});
export const observations=sqliteTable('observations',{
 id:text('id').primaryKey(),incidentId:text('incident_id').notNull().references(()=>incidents.id,{onDelete:'cascade'}),siteId:text('site_id').notNull().references(()=>installations.id,{onDelete:'cascade'}),
 sourceIp:text('source_ip').notNull(),targetIp:text('target_ip'),targetPort:integer('target_port'),protocol:text('protocol').notNull(),username:text('username').notNull(),eventType:text('event_type').notNull(),outcome:text('outcome').notNull(),occurredAt:text('occurred_at'),sourceLabel:text('source_label').notNull(),sourceLat:real('source_lat'),sourceLng:real('source_lng'),precision:text('precision').notNull(),lineNumber:integer('line_number').notNull(),createdAt:text('created_at').notNull(),
},t=>[index('observations_source_idx').on(t.sourceIp),index('observations_incident_idx').on(t.incidentId)]);
export const sourceLocations=sqliteTable('source_locations',{
 sourceIp:text('source_ip').primaryKey(),label:text('label').notNull(),lat:real('lat').notNull(),lng:real('lng').notNull(),precision:text('precision').notNull(),updatedAt:text('updated_at').notNull(),
});
export const threatFeedCache=sqliteTable('threat_feed_cache',{
 source:text('source').primaryKey(),payload:text('payload'),fetchedAt:integer('fetched_at'),lastAttemptAt:integer('last_attempt_at').notNull(),nextAttemptAt:integer('next_attempt_at').notNull(),fetchingUntil:integer('fetching_until').notNull(),lastError:text('last_error'),etag:text('etag'),lastModified:text('last_modified'),
});
export const commanderSessions=sqliteTable('commander_sessions',{
 tokenHash:text('token_hash').primaryKey(),workspaceHash:text('workspace_hash').notNull().references(()=>sessions.tokenHash,{onDelete:'cascade'}),expiresAt:integer('expires_at').notNull(),
},t=>[index('commander_sessions_workspace_idx').on(t.workspaceHash)]);
export const commanderDocuments=sqliteTable('commander_documents',{
 id:text('id').primaryKey(),kind:text('kind').notNull(),incidentId:text('incident_id').references(()=>incidents.id,{onDelete:'set null'}),title:text('title').notNull(),body:text('body').notNull(),status:text('status').notNull(),revision:integer('revision').notNull().default(1),createdAt:text('created_at').notNull(),updatedAt:text('updated_at').notNull(),
});
