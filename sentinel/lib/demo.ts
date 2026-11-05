import {APPROVED_INSTALLATIONS,dummyPocEmail} from './installations';
import {analyzeObservations} from './analysis';
import {reportLogBriefs} from './report-evidence';
import type {Observation} from './types';
import type { Workspace } from './types';
const date='2026-11-04T12:00:00.000Z';
export const demo:Workspace={updatedAt:date,sites:APPROVED_INSTALLATIONS.map(base=>({id:base.id,name:base.name,region:base.region,lat:base.lat,lng:base.lng,contactName:'Demo Duty Officer',contactEmail:dummyPocEmail(base.id),contactPhone:'',createdAt:date,updatedAt:date})),incidents:[
 {id:'demo-inc-1',siteId:'naval-station-norfolk',title:'Simulated Authentication Anomaly',summary:'DEMO ONLY — repeated sign-in failures on a fictional test network. No actual operational information.',severity:'high',status:'reported',hasLog:false,fileName:null,createdAt:date,updatedAt:date},
 {id:'demo-inc-2',siteId:'schriever-space-force-base',title:'Simulated Service Disruption',summary:'DEMO ONLY — a fictional network service disruption is under investigation.',severity:'medium',status:'investigating',hasLog:false,fileName:null,createdAt:date,updatedAt:date},
]};

// Synthetic network evidence used only by the explicitly labeled demo view.

const demoEvents:Observation[]=[];
function event(sourceIp:string,siteId:string,sec:number,extra:Partial<Observation>={}){demoEvents.push({id:'demo-event-'+demoEvents.length,incidentId:siteId==='naval-station-norfolk'?'demo-inc-1':'demo-inc-2',siteId,sourceIp,targetIp:'10.14.0.10',targetPort:443,protocol:'TCP',username:'demo-user',eventType:'network_event',outcome:'blocked',occurredAt:new Date(Date.parse(date)+sec*1000).toISOString(),sourceLabel:'',sourceLat:null,sourceLng:null,precision:'unknown',lineNumber:demoEvents.length+1,createdAt:date,...extra});}
for(let i=0;i<7;i++)event('203.0.113.21','naval-station-norfolk',i*6,{eventType:'authentication',outcome:i===6?'success':'failure',sourceLabel:'Netherlands',sourceLat:52.2,sourceLng:5.3,precision:'country'});
for(let i=0;i<6;i++)event('198.51.100.42','ramstein-air-base',i*7,{targetPort:[22,80,443,445,3389,8080][i],sourceLabel:'Singapore',sourceLat:1.35,sourceLng:103.82,precision:'logged'});
event('198.51.100.42','kadena-air-base',45,{sourceLabel:'Singapore',sourceLat:1.35,sourceLng:103.82,precision:'logged'});
event('198.51.100.42','schriever-space-force-base',50,{sourceLabel:'Singapore',sourceLat:1.35,sourceLng:103.82,precision:'logged'});
for(let i=0;i<22;i++)event('192.0.2.50','schriever-space-force-base',i*2);
demo.incidents[1].targetSiteIds=['schriever-space-force-base','ramstein-air-base','kadena-air-base'];
demo.analysis=analyzeObservations(demoEvents);
const demoBriefs=reportLogBriefs(demoEvents);
demo.incidents=demo.incidents.map(report=>({...report,logBriefs:demoBriefs.get(report.id)??[]}));
