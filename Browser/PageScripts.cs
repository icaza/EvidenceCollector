namespace EvidenceCollector.Browser;

/// <summary>JavaScript snippets evaluated in the evidence page. They only READ the page (and scroll it); nothing is modified.</summary>
internal static class PageScripts
{
    public const string ReadyState = "document.readyState";

    /// <summary>Facts about the page and the browser environment, recorded with every capture.</summary>
    public const string PageInfo = @"(function(){
  var d=document, de=d.documentElement, b=d.body, dt=d.doctype, nav=navigator, w=window, out={};
  out.url=location.href; out.title=d.title; out.readyState=d.readyState; out.characterSet=d.characterSet; out.contentType=d.contentType;
  out.compatMode=d.compatMode; out.lastModified=d.lastModified; out.referrer=d.referrer; out.isSecureContext=w.isSecureContext;
  out.doctype=dt?('<!DOCTYPE '+dt.name+(dt.publicId?' PUBLIC ""'+dt.publicId+'""':'')+(dt.systemId?' ""'+dt.systemId+'""':'')+'>'):null;
  out.userAgent=nav.userAgent; out.language=nav.language; out.languages=Array.prototype.slice.call(nav.languages||[]); out.platform=nav.platform;
  out.cookiesEnabled=nav.cookieEnabled; out.doNotTrack=nav.doNotTrack;
  try{out.timeZone=Intl.DateTimeFormat().resolvedOptions().timeZone;}catch(e){out.timeZone=null;}
  out.devicePixelRatio=w.devicePixelRatio; out.innerWidth=w.innerWidth; out.innerHeight=w.innerHeight; out.outerWidth=w.outerWidth; out.outerHeight=w.outerHeight;
  out.scrollX=w.scrollX; out.scrollY=w.scrollY;
  out.scrollWidth=Math.max(de?de.scrollWidth:0,b?b.scrollWidth:0); out.scrollHeight=Math.max(de?de.scrollHeight:0,b?b.scrollHeight:0);
  out.frames=w.frames.length; out.images=d.images.length; out.links=d.links.length; out.forms=d.forms.length; out.scripts=d.scripts.length;
  out.styleSheets=d.styleSheets.length; out.htmlLength=de?de.outerHTML.length:0;
  return JSON.stringify(out);})()";

    /// <summary>Rendered DOM including the doctype.</summary>
    public const string RenderedDom = @"(function(){var d=document,dt=d.doctype;
  var s=dt?('<!DOCTYPE '+dt.name+(dt.publicId?' PUBLIC ""'+dt.publicId+'""':'')+(!dt.publicId&&dt.systemId?' SYSTEM':'')+(dt.systemId?' ""'+dt.systemId+'""':'')+'>\n'):'';
  return s+(d.documentElement?d.documentElement.outerHTML:'');})()";

    public const string VisibleText = "(function(){var b=document.body;return (document.title||'')+'\\n\\n'+(b?b.innerText:'');})()";

    /// <summary>Every stylesheet the page exposes (external, inline, adopted); cross-origin sheets report a security error instead of rules.</summary>
    public const string StyleSheets = @"(function(){var out=[];
  for(var i=0;i<document.styleSheets.length;i++){var s=document.styleSheets[i];
    var o={index:i,href:s.href,disabled:s.disabled,media:s.media?s.media.mediaText:'',owner:s.ownerNode?s.ownerNode.tagName:null,css:null,error:null};
    try{var r=s.cssRules,t=[];for(var j=0;j<r.length;j++)t.push(r[j].cssText);o.css=t.join('\n');}catch(e){o.error=String((e&&e.name)||e);}
    out.push(o);}
  return JSON.stringify(out);})()";

    /// <summary>Scrolls through the page so lazy-loaded content is requested, then returns to the top. Evaluated with awaitPromise.</summary>
    public static string AutoScroll(int stepDelayMs, int maxDurationMs) => @"(async function(delay,maxMs){
  var started=Date.now(), steps=0, y=0;
  var H=function(){return Math.max(document.body?document.body.scrollHeight:0,document.documentElement?document.documentElement.scrollHeight:0);};
  var vh=window.innerHeight||800, sleep=function(ms){return new Promise(function(r){setTimeout(r,ms);});};
  while(y<H()&&steps<400&&Date.now()-started<maxMs){window.scrollTo(0,y);await sleep(delay);y+=Math.max(200,Math.floor(vh*0.8));steps++;}
  window.scrollTo(0,H());await sleep(delay*2);
  var finalHeight=H();window.scrollTo(0,0);await sleep(Math.max(delay,100));
  return JSON.stringify({steps:steps,finalHeight:finalHeight,elapsedMs:Date.now()-started});})(" + stepDelayMs + "," + maxDurationMs + ")";

    public static string ScrollTo(double x, double y) => $"window.scrollTo({x.ToString(System.Globalization.CultureInfo.InvariantCulture)},{y.ToString(System.Globalization.CultureInfo.InvariantCulture)})";
}
