import countries from './countries.json';
import type {LocationPrecision} from './types';
export const countryLocations=countries as {id:string;name:string;lat:number;lng:number;aliases:string[]}[];
const normalized=(s:string)=>s.trim().toLowerCase().replace(/[^a-z0-9]/g,'');
export function countryLocation(name:string){if(/^(?:unknown(?: region)?|n\/a|none|not available|unspecified|zz|--?)$/i.test(name.trim()))return undefined;return countryLocations.find(c=>c.aliases.some(a=>normalized(a)===normalized(name)));}
// Refresh Russia's approximate country marker for previously saved evidence as
// well as new imports. The legacy center crossed the dateline into Alaska.
// Explicit logged coordinates and analyst coordinate overrides remain evidence.
export function countryMapPoint(label:string,lat:number|null,lng:number|null,precision:LocationPrecision){
 if(precision!=='country'&&precision!=='analyst-country')return {lat,lng};
 const legacy=lat!==null&&lng!==null&&Math.abs(lat-55.704)<.000001&&(Math.abs(lng-202.788)<.000001||Math.abs(lng+157.212)<.000001);
 const russia=countryLocation('RU')!;
 return countryLocation(label)?.id===russia.id||legacy?{lat:russia.lat,lng:russia.lng}:{lat,lng};
}
export function validCoordinates(lat:unknown,lng:unknown):boolean{return lat!==''&&lng!==''&&lat!==null&&lng!==null&&lat!==undefined&&lng!==undefined&&Number.isFinite(Number(lat))&&Number.isFinite(Number(lng))&&Math.abs(Number(lat))<=90&&Math.abs(Number(lng))<=180;}
export function normalizeIp(input:unknown):string|null{
 if(typeof input!=='string')return null;let s=input.trim();const bracket=s.match(/^\[([a-fA-F\d:]+)\](?::\d+)?$/);if(bracket)s=bracket[1];else if(/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(s))s=s.split(':')[0];
 if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)){const parts=s.split('.');return parts.every(x=>Number(x)<=255)?parts.map(Number).join('.'):null;}
 if(s.includes(':')){try{const h=new URL('http://['+s+']/').hostname;return h.slice(1,-1).toLowerCase();}catch{}}
 return null;
}
export function ipScope(ip:string):'public'|'private/reserved'{
 if(ip.includes(':'))return /^(?:fc|fd|fe[89ab]|ff|2001:db8:)/i.test(ip)||ip==='::1'||ip==='::'||ip.startsWith('::ffff:')?'private/reserved':'public';
 const [a,b,c]=ip.split('.').map(Number);return a===10||a===127||a===0||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0&&(c===0||c===2))||a===198&&(b===18||b===19||b===51&&c===100)||a===203&&b===0&&c===113||a===100&&b>=64&&b<=127?'private/reserved':'public';
}
// Great-circle interpolation, including deterministic antipodal handling.
export function greatCircle(a:{lat:number;lng:number},b:{lat:number;lng:number},t:number){const r=Math.PI/180;const vec=(p:typeof a)=>[Math.cos(p.lat*r)*Math.cos(p.lng*r),Math.cos(p.lat*r)*Math.sin(p.lng*r),Math.sin(p.lat*r)];const u=vec(a),v=vec(b),dot=Math.max(-1,Math.min(1,u.reduce((s,x,i)=>s+x*v[i],0))),angle=Math.acos(dot);let q:number[];
 if(angle<1e-6)q=u;else if(Math.PI-angle<1e-5){let axis=Math.abs(u[2])<.9?[0,0,1]:[1,0,0];const cross=[u[1]*axis[2]-u[2]*axis[1],u[2]*axis[0]-u[0]*axis[2],u[0]*axis[1]-u[1]*axis[0]],len=Math.hypot(...cross);axis=cross.map(x=>x/len);q=u.map((x,i)=>x*Math.cos(Math.PI*t)+axis[i]*Math.sin(Math.PI*t));}else{const s=Math.sin(angle),x=Math.sin((1-t)*angle)/s,y=Math.sin(t*angle)/s;q=u.map((z,i)=>z*x+v[i]*y);}
 return {lat:Math.atan2(q[2],Math.hypot(q[0],q[1]))/r,lng:Math.atan2(q[1],q[0])/r};
}
