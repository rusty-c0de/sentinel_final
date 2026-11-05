export type IntelSourceId='cisa'|'sans'|'nist';
export interface IntelEntry {
 id:string;source:IntelSourceId;title:string;summary:string;url:string;cve:string|null;
 publishedAt:string|null;updatedAt:string|null;dateLabel:string;kind:'known-exploited'|'research'|'vulnerability';
 severity:'critical'|'high'|'medium'|'low'|'unrated';score:number|null;scoreSource:string|null;
 action:string|null;dueDate:string|null;ransomwareKnown:boolean;tags:string[];
}
export interface IntelSourceState {
 id:IntelSourceId;name:string;description:string;homepage:string;feedUrl:string;
 status:'current'|'stale'|'unavailable'|'checking';checkedAt:string|null;attemptedAt:string|null;nextCheckAt:string;
 latestEntryAt:string|null;sourceUpdatedAt:string|null;count:number;totalAvailable:number|null;error:string|null;note:string;
}
export interface ThreatIntelFeed {items:IntelEntry[];sources:IntelSourceState[];servedAt:string;nextRefreshAt:string;refreshIntervalSeconds:number;}
