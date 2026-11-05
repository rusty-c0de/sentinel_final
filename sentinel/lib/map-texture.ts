export type MapRing=number[][];
// Keep dateline crossings local instead of drawing a chord across the world.
export function unwrapMapRing(ring:MapRing):MapRing{
 if(!ring.length)return [];const out:MapRing=[[...ring[0]]];
 for(let i=1;i<ring.length;i++){let [lon,lat]=ring[i];const previous=out[out.length-1][0];while(lon-previous>180)lon-=360;while(lon-previous< -180)lon+=360;out.push([lon,lat]);}
 const first=out[0],last=out[out.length-1];
 // A ring winding around a pole must close along that pole, not across land.
 if(Math.abs(last[0]-first[0])>180){const pole=ring.reduce((s,p)=>s+p[1],0)/ring.length<0?-90:90;out.push([last[0],pole],[first[0],pole],[...first]);}
 return out;
}
export function paintMapTexture(ctx:CanvasRenderingContext2D,polygons:number[][][][],width:number,height:number){
 ctx.clearRect(0,0,width,height);ctx.fillStyle='#fff';
 for(const polygon of polygons){const rings=polygon.map(unwrapMapRing);if(!rings[0]?.length)continue;const center=rings[0].reduce((s,p)=>s+p[0],0)/rings[0].length;
  for(const shift of [-720,-360,0,360,720]){ctx.beginPath();for(const ring of rings){if(!ring.length)continue;const middle=ring.reduce((s,p)=>s+p[0],0)/ring.length;const align=Math.round((center-middle)/360)*360;ring.forEach(([lon,lat],i)=>{const x=(lon+align+shift+180)/360*width,y=(90-lat)/180*height;i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.closePath();}ctx.fill('evenodd');}
 }
}
