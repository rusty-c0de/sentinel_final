'use client';
import {useEffect,useRef,useState} from 'react';
import {Plus,Minus,Scan,RotateCcw} from 'lucide-react';
import type {Installation,Incident,ThreatFlow} from '../../lib/types';
import {siteSeverity} from '../../lib/types';
import {greatCircle} from '../../lib/geo';
import {paintMapTexture} from '../../lib/map-texture';
const RAD=Math.PI/180;
const DEFAULT_VIEW={lat:39.8,lng:-98.6};
const clamp=(n:number,a:number,b:number)=>Math.max(a,Math.min(b,n));
const wrap=(v:number)=>((v+180)%360+360)%360-180;
type Polygon=number[][][];
export default function Globe({sites,incidents,selected,onSelect,focusId,decorative=false,flows=[],focusRoute,onSourceSelect}:{sites:Installation[];incidents:Incident[];selected:string|null;onSelect:(id:string)=>void;focusId?:string|null;decorative?:boolean;flows?:ThreatFlow[];focusRoute?:ThreatFlow|null;onSourceSelect?:(ip:string)=>void}){
 const canvas=useRef<HTMLCanvasElement>(null),container=useRef<HTMLDivElement>(null);
 const control=useRef<{zoom:(factor:number)=>void;reset:()=>void;focus:(site:{lat:number;lng:number})=>void}|null>(null);
 const props=useRef({sites,incidents,selected,onSelect,flows,onSourceSelect,focusRoute});props.current={sites,incidents,selected,onSelect,flows,onSourceSelect,focusRoute};
 const [view,setView]=useState(DEFAULT_VIEW),[error,setError]=useState(false);
 const lastFocus=useRef<string|null>(null);
 useEffect(()=>{
  const el=canvas.current,holder=container.current;if(!el||!holder)return;const ctx=el.getContext('2d');if(!ctx){setError(true);return;}
  let width=0,height=0,cx=0,cy=0,radius=0,zoom=1,lat=DEFAULT_VIEW.lat,lon=DEFAULT_VIEW.lng,dirty=true,frame=0,destroyed=false,hover:string|null=null,hoverSource:string|null=null;
  let drag:{x:number;y:number;lon:number;lat:number;moved:boolean;id:number}|null=null;
  const sphere=document.createElement('canvas'),sctx=sphere.getContext('2d')!;
  const texture=document.createElement('canvas');texture.width=2048;texture.height=1024;const tctx=texture.getContext('2d')!;
  let pixels:Uint8ClampedArray|null=null;
  const notify=()=>setView({lat,lng:lon});
  const resize=()=>{const rect=holder.getBoundingClientRect();width=rect.width;height=rect.height;const dpr=Math.min(devicePixelRatio||1,2);el.width=Math.round(width*dpr);el.height=Math.round(height*dpr);ctx.setTransform(dpr,0,0,dpr,0,0);cx=width/2;cy=height/2;radius=Math.min(width*.395,height*.407)*zoom;dirty=true;};
  const project=(lng:number,la:number,alt=0)=>{const a=la*RAD,b=(lng-lon)*RAD,c=lat*RAD;const depth=Math.sin(c)*Math.sin(a)+Math.cos(c)*Math.cos(a)*Math.cos(b);return {x:cx+radius*(1+alt)*Math.cos(a)*Math.sin(b),y:cy-radius*(1+alt)*(Math.cos(c)*Math.sin(a)-Math.sin(c)*Math.cos(a)*Math.cos(b)),depth};};
  const isLand=(lng:number,la:number)=>{if(!pixels)return 0;const tx=clamp(Math.floor((wrap(lng)+180)/360*2048),0,2047),ty=clamp(Math.floor((90-la)/180*1024),0,1023);return pixels[(ty*2048+tx)*4+3]/255;};
  fetch('/world.json').then(r=>{if(!r.ok)throw Error('map');return r.json();}).then((data)=>{const polygons=data as Polygon[];if(destroyed)return;paintMapTexture(tctx,polygons,2048,1024);pixels=tctx.getImageData(0,0,2048,1024).data;dirty=true;}).catch(()=>{if(!destroyed)setError(true);});
  function update(){
   const size=Math.max(2,Math.min(760,Math.ceil(radius*2)));sphere.width=size;sphere.height=size;const image=sctx.createImageData(size,size),out=image.data,mid=size/2,c=lat*RAD;
   for(let y=0;y<size;y++)for(let x=0;x<size;x++){const nx=(x+.5-mid)/mid,ny=(mid-y-.5)/mid,sq=nx*nx+ny*ny;if(sq>1)continue;const z=Math.sqrt(1-sq);const a=Math.asin(clamp(ny*Math.cos(c)+z*Math.sin(c),-1,1)),b=lon*RAD+Math.atan2(nx,z*Math.cos(c)-ny*Math.sin(c));const land=isLand(b/RAD,a/RAD),light=clamp(.67+z*.25-nx*.15+ny*.12,.3,1),rim=Math.pow(1-z,4);const i=(y*size+x)*4;out[i]=Math.round((10+land*38)*light+rim*10);out[i+1]=Math.round((30+land*58)*light+rim*30);out[i+2]=Math.round((36+land*49)*light+rim*31);out[i+3]=255;}
   sctx.putImageData(image,0,0);sctx.save();sctx.translate(size/2,size/2);const scale=size/(radius*2);sctx.scale(scale,scale);sctx.translate(-cx,-cy);
   // Land dots follow the same geographic projection as installation markers.
   sctx.fillStyle='rgba(172,204,174,.28)';for(let la=-81;la<85;la+=3){const step=3/Math.max(.25,Math.cos(la*RAD));for(let lo=-180;lo<180;lo+=step){if(isLand(lo,la)>.8){const p=project(lo,la);if(p.depth>.08){sctx.beginPath();sctx.arc(p.x,p.y,.65,0,Math.PI*2);sctx.fill();}}}}
   sctx.restore();dirty=false;
  }
  const drawLine=(points:number[][])=>{ctx!.beginPath();let started=false;for(const[lo,la]of points){const p=project(lo,la);if(p.depth<=.01){started=false;continue;}started?ctx!.lineTo(p.x,p.y):ctx!.moveTo(p.x,p.y);started=true;}ctx!.stroke();};
  const routeCache=new Map<string,{lat:number;lng:number}[]>();
  function drawableFlows(){return props.current.flows.filter(f=>f.sourceLat!==null&&f.sourceLng!==null&&props.current.sites.some(s=>s.id===f.targetSiteId)).sort((a,b)=>(b.id===props.current.focusRoute?.id?3:b.targetSiteId===props.current.selected?1:0)-(a.id===props.current.focusRoute?.id?3:a.targetSiteId===props.current.selected?1:0)).slice(0,100);}
  function flowPoints(f:ThreatFlow){const target=props.current.sites.find(s=>s.id===f.targetSiteId)!;const key=f.id+':'+f.sourceLat+':'+f.sourceLng+':'+target.lat+':'+target.lng;let points=routeCache.get(key);if(!points){points=Array.from({length:65},(_,i)=>greatCircle({lat:f.sourceLat!,lng:f.sourceLng!},target,i/64));routeCache.set(key,points);if(routeCache.size>300)routeCache.delete(routeCache.keys().next().value!);}return points;}
  function sourceHit(x:number,y:number){return drawableFlows().find(f=>{const p=project(f.sourceLng!,f.sourceLat!);return p.depth>.02&&Math.hypot(x-p.x,y-p.y)<14;});}
  function drawFlows(time:number){
   const drawnSources=new Set<string>();
   for(const f of drawableFlows()){const selected=props.current.selected===f.targetSiteId,points=flowPoints(f);ctx!.beginPath();let started=false;for(let i=0;i<points.length;i++){const v=points[i],p=project(v.lng,v.lat,Math.sin(i/64*Math.PI)*.14);if(p.depth<.012){started=false;continue;}started?ctx!.lineTo(p.x,p.y):ctx!.moveTo(p.x,p.y);started=true;}ctx!.strokeStyle=selected?'rgba(240,165,112,.8)':'rgba(213,158,108,.32)';ctx!.lineWidth=selected?1.8:1;ctx!.setLineDash(f.precision.includes('country')?[3,4]:[]);ctx!.stroke();ctx!.setLineDash([]);
    const i=reduce?45:Math.floor((time/70+f.eventCount)%60)+2,v=points[i],next=points[Math.min(i+1,64)],a=project(v.lng,v.lat,Math.sin(i/64*Math.PI)*.14),b=project(next.lng,next.lat,Math.sin(Math.min(i+1,64)/64*Math.PI)*.14);if(a.depth>.02&&b.depth>.02){ctx!.save();ctx!.translate(a.x,a.y);ctx!.rotate(Math.atan2(b.y-a.y,b.x-a.x));ctx!.fillStyle=selected?'#f4b27c':'#b99570';ctx!.beginPath();ctx!.moveTo(4,0);ctx!.lineTo(-3,-2.4);ctx!.lineTo(-3,2.4);ctx!.closePath();ctx!.fill();ctx!.restore();}
    const sourceKey=f.sourceIp;if(drawnSources.has(sourceKey))continue;drawnSources.add(sourceKey);const p=project(f.sourceLng!,f.sourceLat!);if(p.depth<.02)continue;ctx!.save();ctx!.translate(p.x,p.y);ctx!.rotate(Math.PI/4);ctx!.fillStyle='#efa875';ctx!.shadowColor='#efa875';ctx!.shadowBlur=9;ctx!.fillRect(-3,-3,6,6);ctx!.shadowBlur=0;ctx!.strokeStyle='rgba(239,168,117,.35)';ctx!.strokeRect(-6,-6,12,12);ctx!.restore();
    if(hoverSource===f.sourceIp){const label=f.sourceIp+' · '+(f.sourceLabel||'Reported source'),w=ctx!.measureText(label).width+20,x=clamp(p.x+12,8,width-w-8),y=clamp(p.y-14,35,height-10);ctx!.fillStyle='#1e2d2b';ctx!.beginPath();ctx!.roundRect(x,y-22,w,29,4);ctx!.fill();ctx!.font='10px system-ui';ctx!.textAlign='left';ctx!.fillStyle='#f0b98d';ctx!.fillText(label,x+9,y-3);}
   }
  }
  let last=0;
  const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
  const render=(time:number)=>{if(destroyed)return;frame=requestAnimationFrame(render);if(time-last<40)return;last=time;ctx.clearRect(0,0,width,height);
   const glow=ctx.createRadialGradient(cx,cy,radius*.6,cx,cy,radius*1.35);glow.addColorStop(0,'rgba(79,156,140,0)');glow.addColorStop(.55,'rgba(79,156,140,.075)');glow.addColorStop(1,'rgba(79,156,140,0)');ctx.fillStyle=glow;ctx.fillRect(0,0,width,height);
   if(dirty)update();ctx.drawImage(sphere,cx-radius,cy-radius,radius*2,radius*2);
   ctx.strokeStyle='rgba(126,173,163,.12)';ctx.lineWidth=.7;for(let la=-60;la<=60;la+=30){const p=[];for(let lo=-180;lo<=180;lo+=3)p.push([lo,la]);drawLine(p);}for(let lo=-180;lo<180;lo+=30){const p=[];for(let la=-90;la<=90;la+=3)p.push([lo,la]);drawLine(p);}
   ctx.beginPath();ctx.arc(cx,cy,radius,0,Math.PI*2);ctx.strokeStyle='rgba(145,192,174,.35)';ctx.lineWidth=1;ctx.stroke();ctx.beginPath();ctx.arc(cx,cy,radius+16,0,Math.PI*2);ctx.setLineDash([1,8]);ctx.strokeStyle='rgba(138,164,159,.23)';ctx.stroke();ctx.setLineDash([]);
   ctx.font='10px ui-monospace, monospace';ctx.fillStyle='#6d8583';ctx.textAlign='center';ctx.fillText('N',cx,cy-radius-28);
   drawFlows(time);
   for(const site of props.current.sites){const p=project(site.lng,site.lat);if(p.depth<.04)continue;const severity=siteSeverity(site.id,props.current.incidents),active=severity!=='none',chosen=props.current.selected===site.id;const color=severity==='critical'||severity==='high'?'#f2917d':severity==='medium'?'#80b7ef':severity==='low'?'#b5c9dd':'#8fc7ff';
    if(active){const pulse=reduce?.4:(Math.sin(time/600)+1)/2;ctx.beginPath();ctx.arc(p.x,p.y,10+pulse*8,0,Math.PI*2);ctx.strokeStyle=color;ctx.globalAlpha=.25*(1-pulse);ctx.stroke();ctx.globalAlpha=1;}
    if(chosen||hover===site.id){ctx.beginPath();ctx.arc(p.x,p.y,11,0,Math.PI*2);ctx.strokeStyle=color;ctx.lineWidth=1;ctx.stroke();}
    ctx.shadowColor=color;ctx.shadowBlur=12;ctx.fillStyle=color;ctx.beginPath();ctx.arc(p.x,p.y,chosen?5:4,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;ctx.fillStyle='#f4f6ec';ctx.beginPath();ctx.arc(p.x,p.y,1.4,0,Math.PI*2);ctx.fill();
    if(chosen||hover===site.id){ctx.font='500 11px system-ui, sans-serif';const label=site.name.length>30?site.name.slice(0,28)+'…':site.name,w=ctx.measureText(label).width+20,x=clamp(p.x+15,8,width-w-8),y=clamp(p.y-15,32,height-10);ctx.fillStyle='#17282d';ctx.beginPath();ctx.roundRect(x,y-22,w,30,5);ctx.fill();ctx.strokeStyle='#415653';ctx.stroke();ctx.fillStyle='#edf1e9';ctx.textAlign='left';ctx.fillText(label,x+10,y-3);}
   }
  };
  function hit(x:number,y:number){return props.current.sites.map(s=>({site:s,p:project(s.lng,s.lat)})).filter(v=>v.p.depth>.04&&Math.hypot(x-v.p.x,y-v.p.y)<17).sort((a,b)=>Math.hypot(x-a.p.x,y-a.p.y)-Math.hypot(x-b.p.x,y-b.p.y))[0]?.site;}
  const position=(e:PointerEvent)=>{const rect=el!.getBoundingClientRect();return {x:e.clientX-rect.left,y:e.clientY-rect.top};};
  const down=(e:PointerEvent)=>{if(decorative||(e.pointerType==='mouse'&&e.button!==0)||drag)return;drag={x:e.clientX,y:e.clientY,lon,lat,moved:false,id:e.pointerId};el.setPointerCapture(e.pointerId);el.style.cursor='grabbing';};
  const move=(e:PointerEvent)=>{if(decorative)return;if(drag&&e.pointerId===drag.id){const dx=e.clientX-drag.x,dy=e.clientY-drag.y;if(Math.hypot(dx,dy)>5)drag.moved=true;if(drag.moved){lon=wrap(drag.lon-dx*.25);lat=clamp(drag.lat+dy*.22,-85,85);dirty=true;hover=null;hoverSource=null;}}else{const p=position(e);hover=hit(p.x,p.y)?.id??null;hoverSource=sourceHit(p.x,p.y)?.sourceIp??null;el.style.cursor=hover||hoverSource?'pointer':'grab';}};
  const up=(e:PointerEvent)=>{if(!drag||e.pointerId!==drag.id)return;if(!drag.moved){const p=position(e),s=hit(p.x,p.y);if(s)props.current.onSelect(s.id);else{const source=sourceHit(p.x,p.y);if(source)props.current.onSourceSelect?.(source.sourceIp);}}drag=null;if(el.hasPointerCapture(e.pointerId))el.releasePointerCapture(e.pointerId);el.style.cursor='grab';notify();};
  const cancel=()=>{drag=null;hover=null;};const leave=()=>{hover=null;hoverSource=null;};
  const wheel=(e:WheelEvent)=>{if(decorative)return;e.preventDefault();zoom=clamp(zoom*(e.deltaY>0?.94:1.06),.65,1.65);resize();};
  const key=(e:KeyboardEvent)=>{let handled=true;switch(e.key){case'ArrowLeft':lon=wrap(lon-8);break;case'ArrowRight':lon=wrap(lon+8);break;case'ArrowUp':lat=clamp(lat+8,-85,85);break;case'ArrowDown':lat=clamp(lat-8,-85,85);break;case'+':case'=':zoom=clamp(zoom*1.1,.65,1.65);resize();break;case'-':zoom=clamp(zoom/1.1,.65,1.65);resize();break;default:handled=false;}if(handled){e.preventDefault();dirty=true;notify();}};
  control.current={zoom:f=>{zoom=clamp(zoom*f,.65,1.65);resize();},reset:()=>{lat=DEFAULT_VIEW.lat;lon=DEFAULT_VIEW.lng;zoom=1;resize();notify();},focus:s=>{lat=clamp(s.lat,-85,85);lon=s.lng;dirty=true;notify();}};
  const ro=new ResizeObserver(resize);ro.observe(holder);resize();frame=requestAnimationFrame(render);
  el.addEventListener('pointerdown',down);el.addEventListener('pointermove',move);el.addEventListener('pointerup',up);el.addEventListener('pointercancel',cancel);el.addEventListener('pointerleave',leave);el.addEventListener('wheel',wheel,{passive:false});el.addEventListener('keydown',key);
  return()=>{destroyed=true;cancelAnimationFrame(frame);ro.disconnect();control.current=null;el.removeEventListener('pointerdown',down);el.removeEventListener('pointermove',move);el.removeEventListener('pointerup',up);el.removeEventListener('pointercancel',cancel);el.removeEventListener('pointerleave',leave);el.removeEventListener('wheel',wheel);el.removeEventListener('keydown',key);};
 },[decorative]);
 useEffect(()=>{const site=sites.find(s=>s.id===focusId);const key=site?`${site.id}:${site.lat}:${site.lng}`:null;if(site&&key!==lastFocus.current&&control.current){control.current.focus(site);lastFocus.current=key;}},[focusId,sites]);
 useEffect(()=>{if(focusRoute&&focusRoute.sourceLat!==null&&focusRoute.sourceLng!==null){const target=sites.find(s=>s.id===focusRoute.targetSiteId);if(target)control.current?.focus(greatCircle({lat:focusRoute.sourceLat,lng:focusRoute.sourceLng},target,.5));}},[focusRoute]);
 return <div ref={container} className={`globe-container ${decorative?'globe-decorative':''}`}><canvas ref={canvas} tabIndex={decorative?-1:0} role="img" aria-label="Interactive world globe. Drag or use arrow keys to rotate. Use plus and minus to zoom. Select locations using the installation list."/>{!decorative&&<><div className="globe-corner"><span className="tiny-square"/>ORTHOGRAPHIC VIEW<span className="globe-corner-sub">{Math.abs(view.lat).toFixed(1)}° {view.lat>=0?'N':'S'} / {Math.abs(view.lng).toFixed(1)}° {view.lng>=0?'E':'W'}</span></div><div className="globe-controls"><button onClick={()=>control.current?.zoom(1.15)} aria-label="Zoom In"><Plus size={17}/></button><button onClick={()=>control.current?.zoom(1/1.15)} aria-label="Zoom Out"><Minus size={17}/></button><span/><button onClick={()=>control.current?.reset()} aria-label="Reset Globe View"><RotateCcw size={16}/></button></div><div className="globe-instruction"><Scan size={13}/> Drag to rotate <span>·</span><span className="desktop-gesture">Scroll to zoom</span><span className="mobile-gesture">Use + / − to zoom</span></div><a className="map-credit" href="/map-attribution.txt" target="_blank" rel="noreferrer">Natural Earth</a></>}{error&&<div className="map-error">Map detail unavailable. Your locations remain available in the list below.</div>}</div>;
}
