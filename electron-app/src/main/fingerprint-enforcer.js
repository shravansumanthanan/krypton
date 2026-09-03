'use strict';

/**
 * FingerprintEnforcer — main-process fingerprint mitigation service.
 *
 * Three policy levels:
 *   'off'      → no intervention
 *   'standard' → Canvas/Audio/WebGL noise injection via injected JS
 *   'strict'   → Block canvas.toDataURL, getImageData, AudioContext, WebGL readPixels
 *
 * Security: No key material. Policy string only crosses IPC.
 */

const POLICIES = new Set(['off', 'standard', 'strict']);

// Per-session noise seed — regenerated on each launch, never persisted.
const SESSION_NOISE_SEED = Math.floor(Math.random() * 0xffffff)
  .toString(16)
  .padStart(6, '0');

function buildNoiseScript(level) {
  if (level === 'off') return '';

  if (level === 'strict') {
    return `(function(){
  'use strict';
  const blocked=()=>{throw new Error('KryptonBrowser: fingerprinting API blocked');};
  try{const p=HTMLCanvasElement.prototype;Object.defineProperty(p,'toDataURL',{get:blocked,configurable:false});Object.defineProperty(p,'toBlob',{get:blocked,configurable:false});const c=CanvasRenderingContext2D.prototype;Object.defineProperty(c,'getImageData',{get:blocked,configurable:false});}catch(e){}
  try{Object.defineProperty(window,'AudioContext',{get:blocked,configurable:false});Object.defineProperty(window,'webkitAudioContext',{get:blocked,configurable:false});}catch(e){}
  try{const w=WebGLRenderingContext.prototype;Object.defineProperty(w,'readPixels',{get:blocked,configurable:false});const w2=WebGL2RenderingContext.prototype;Object.defineProperty(w2,'readPixels',{get:blocked,configurable:false});}catch(e){}
})();`;
  }

  // standard: per-session noise
  return `(function(){
  'use strict';
  const SEED=0x${SESSION_NOISE_SEED};
  function noise(n){return(((n^SEED)*0x9e3779b9)>>>0)%10-5;}
  try{
    const orig=HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL=function(...a){
      try{
        if(this.width>0 && this.height>0 && this.width<=300 && this.height<=300){
          const ctx=this.getContext&&this.getContext('2d');
          if(ctx && typeof ctx.getImageData==='function'){
            const d=ctx.getImageData(0,0,this.width,this.height);
            for(let i=0;i<d.data.length;i+=4){
              d.data[i]=Math.min(255,Math.max(0,d.data[i]+noise(i)));
              d.data[i+1]=Math.min(255,Math.max(0,d.data[i+1]+noise(i+1)));
              d.data[i+2]=Math.min(255,Math.max(0,d.data[i+2]+noise(i+2)));
            }
            ctx.putImageData(d,0,0);
          }
        }
      }catch(err){}
      return orig.apply(this,a);
    };
  }catch(e){}
  try{
    const orig=AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData=function(ch){
      const d=orig.call(this,ch);
      try{
        if(d && d.length>0 && d.length<=5000){
          for(let i=0;i<d.length;i++)d[i]+=noise(i)*0.0001;
        }
      }catch(err){}
      return d;
    };
  }catch(e){}
  try{
    const orig=WebGLRenderingContext.prototype.readPixels;
    WebGLRenderingContext.prototype.readPixels=function(...a){
      orig.apply(this,a);
      try{
        const p=a[6];
        if(p instanceof Uint8Array && p.length>0 && p.length<=65536){
          for(let i=0;i<p.length;i+=4){
            p[i]=Math.min(255,Math.max(0,p[i]+noise(i)));
            p[i+1]=Math.min(255,Math.max(0,p[i+1]+noise(i+1)));
            p[i+2]=Math.min(255,Math.max(0,p[i+2]+noise(i+2)));
          }
        }
      }catch(err){}
    };
  }catch(e){}
})();`;
}

class FingerprintEnforcer {
  constructor() {
    this._policy = 'standard';
    this._script = buildNoiseScript('standard');
  }

  setPolicy(level) {
    if (!POLICIES.has(level)) return false;
    this._policy = level;
    this._script = buildNoiseScript(level);
    return true;
  }

  getPolicy() {
    return this._policy;
  }

  /**
   * Hook into a WebContents to inject the noise/blocking script on every navigation.
   * Call this for the mainWindow webContents and for each webview.
   */
  injectIntoWebContents(webContents) {
    if (!webContents || webContents.isDestroyed()) return;
    if (this._policy === 'off' || !this._script) return;

    const inject = () => {
      if (webContents.isDestroyed()) return;
      webContents.executeJavaScript(this._script).catch(() => {});
    };
    webContents.on('did-navigate', inject);
    webContents.on('did-navigate-in-page', inject);
  }

  /**
   * Apply extra response headers for strict mode.
   * Call inside your existing onHeadersReceived callback.
   * @param {object} headers - mutable responseHeaders object
   * @param {string} [url] - request URL
   */
  applyHeaders(headers, url = '') {
    const isMedia =
      typeof url === 'string' &&
      (/googlevideo\.com|youtube\.com\/videoplayback/i.test(url) ||
        (headers['content-type'] && /(?:video|audio)\//i.test(headers['content-type'][0])));

    if (this._policy === 'strict') {
      headers['Permissions-Policy'] = [
        'camera=(), microphone=(), geolocation=(), interest-cohort=(), display-capture=(), usb=(), serial=(), hid=()',
      ];
      if (!isMedia) {
        headers['Cross-Origin-Resource-Policy'] = ['same-origin'];
        headers['Cross-Origin-Embedder-Policy'] = ['require-corp'];
      }
    }
    if (this._policy !== 'off' && !isMedia) {
      delete headers['etag'];
      delete headers['ETag'];
    }
    return headers;
  }
}

module.exports = new FingerprintEnforcer();
