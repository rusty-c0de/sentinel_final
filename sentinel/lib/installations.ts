// The approved installation catalog is the single source of truth for UI and API targets.
// Coordinates are approximate map reference points, not facility or gate locations.
export interface ApprovedInstallation {id:string;name:string;region:string;lat:number;lng:number;aliases:readonly string[];}
export const APPROVED_INSTALLATIONS:readonly ApprovedInstallation[]=[
 {id:'fort-bragg',name:'Fort Bragg',region:'North Carolina, United States',lat:35.139,lng:-79.006,aliases:[]},
 {id:'fort-campbell',name:'Fort Campbell',region:'Kentucky / Tennessee, United States',lat:36.663,lng:-87.477,aliases:[]},
 {id:'naval-station-norfolk',name:'Naval Station Norfolk',region:'Virginia, United States',lat:36.946,lng:-76.302,aliases:['NS Norfolk']},
 {id:'naval-base-san-diego',name:'Naval Base San Diego',region:'California, United States',lat:32.684,lng:-117.119,aliases:['NB San Diego']},
 {id:'joint-base-san-antonio',name:'Joint Base San Antonio',region:'Texas, United States',lat:29.459,lng:-98.437,aliases:['JBSA']},
 {id:'wright-patterson-afb',name:'Wright-Patterson Air Force Base',region:'Ohio, United States',lat:39.826,lng:-84.048,aliases:['Wright Patterson AFB','Wright-Patterson AFB']},
 {id:'patrick-space-force-base',name:'Patrick Space Force Base',region:'Florida, United States',lat:28.236,lng:-80.610,aliases:['Patrick SFB']},
 {id:'schriever-space-force-base',name:'Schriever Space Force Base',region:'Colorado, United States',lat:38.806,lng:-104.526,aliases:['Schriever SFB']},
 {id:'camp-pendleton',name:'Marine Corps Base Camp Pendleton',region:'California, United States',lat:33.303,lng:-117.354,aliases:['Camp Pendleton','MCB Camp Pendleton']},
 {id:'quantico',name:'Marine Corps Base Quantico',region:'Virginia, United States',lat:38.502,lng:-77.306,aliases:['Quantico','MCB Quantico']},
 {id:'camp-humphreys',name:'Camp Humphreys',region:'Pyeongtaek, South Korea',lat:36.966,lng:127.031,aliases:['USAG Humphreys','U.S. Army Garrison Humphreys']},
 {id:'kadena-air-base',name:'Kadena Air Base',region:'Okinawa, Japan',lat:26.351,lng:127.770,aliases:['Kadena Air Force Base','Kadena AB']},
 {id:'ramstein-air-base',name:'Ramstein Air Base',region:'Rhineland-Palatinate, Germany',lat:49.437,lng:7.600,aliases:['Ramenstein Air Base','Ramstein AB']},
 {id:'joint-base-pearl-harbor-hickam',name:'Joint Base Pearl Harbor-Hickam',region:'Hawaii, United States',lat:21.349,lng:-157.946,aliases:['JBPHH','Joint Base Pearl Harbor - Hickam']},
 {id:'naval-air-station-jacksonville',name:'Naval Air Station Jacksonville',region:'Florida, United States',lat:30.235,lng:-81.681,aliases:['NAS Jacksonville']},
];
const normalized=(value:string)=>value.normalize('NFKC').trim().toLowerCase().replace(/[\s\u2010-\u2015_-]+/g,' ');
const byId=new Map(APPROVED_INSTALLATIONS.map(base=>[base.id,base]));
const byName=new Map(APPROVED_INSTALLATIONS.flatMap(base=>[base.name,...base.aliases].map(name=>[normalized(name),base] as const)));
export function installationById(value:unknown){return typeof value==='string'?byId.get(value):undefined;}
export function resolveInstallation(value:unknown){return typeof value==='string'?(byId.get(value)||byName.get(normalized(value))):undefined;}
// Reserved, non-deliverable addresses for demonstration; saved real contacts take precedence.
export function dummyPocEmail(id:string){return byId.has(id)?`${id}.poc@example.invalid`:'';}
