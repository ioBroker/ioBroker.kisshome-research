(()=>{var M={56046:(a,u,n)=>{Promise.all([n.e("webpack_sharing_consume_default_react_react"),n.e("webpack_sharing_consume_default_prop-types_prop-types"),n.e("webpack_sharing_consume_default_react-dom_react-dom"),n.e("webpack_sharing_consume_default_mui_icons-material_mui_icons-material-webpack_sharing_consume-6275fc"),n.e("webpack_sharing_consume_default_iobroker_adapter-react-v5_iobroker_adapter-react-v5"),n.e("src_ConfigCustomInstancesSelector_jsx"),n.e("src_bootstrap_jsx")]).then(n.bind(n,38733))}},B={};function e(a){var u=B[a];if(u!==void 0)return u.exports;var n=B[a]={id:a,loaded:!1,exports:{}};return M[a].call(n.exports,n,n.exports,e),n.loaded=!0,n.exports}e.m=M,e.c=B,e.amdD=function(){throw new Error("define cannot be used indirect")},e.n=a=>{var u=a&&a.__esModule?()=>a.default:()=>a;return e.d(u,{a:u}),u},e.d=(a,u)=>{for(var n in u)e.o(u,n)&&!e.o(a,n)&&Object.defineProperty(a,n,{enumerable:!0,get:u[n]})},e.f={},e.e=a=>Promise.all(Object.keys(e.f).reduce((u,n)=>(e.f[n](a,u),u),[])),e.u=a=>"static/js/"+a+"."+{webpack_sharing_consume_default_react_react:"dbf809cc","webpack_sharing_consume_default_prop-types_prop-types":"a742cf33","webpack_sharing_consume_default_react-dom_react-dom":"5f4509c2","webpack_sharing_consume_default_mui_icons-material_mui_icons-material-webpack_sharing_consume-6275fc":"705db7ad","webpack_sharing_consume_default_iobroker_adapter-react-v5_iobroker_adapter-react-v5":"d3035c9b",src_ConfigCustomInstancesSelector_jsx:"0b7c3813",src_bootstrap_jsx:"bfefe7e3","vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197":"8bbbbf8a","vendors-node_modules_react-color_es_index_js-node_modules_react-icons_lib_index_mjs":"5c06a283","vendors-node_modules_mui_material_colors_index_js-node_modules_mui_material_styles_index_js":"96adb37c","vendors-node_modules_iobroker_adapter-react-v5_index_js-node_modules_mui_material_styles_cssU-325e90":"31d290b7","webpack_sharing_consume_default_react-dropzone_react-dropzone":"967b3d88","node_modules_iobroker_adapter-react-v5_assets_devices_sync_recursive_-node_modules_iobroker_a-de23730":"79a7a687","vendors-node_modules_mui_material_FilledInput_FilledInput_js":"a5ff8db2","vendors-node_modules_iobroker_json-config_build_index_js":"95e0d3f7","webpack_sharing_consume_default_mui_x-date-pickers_mui_x-date-pickers-webpack_sharing_consume-9f1a2d":"a399f706",_91570:"cbc32633","vendors-node_modules_mui_icons-material_esm_index_js":"38eac2d1","vendors-node_modules_mui_material_Button_Button_js-node_modules_mui_material_Chip_Chip_js-nod-a86d80":"4281d948","vendors-node_modules_mui_material_index_js":"204a2035","vendors-node_modules_mui_x-date-pickers_index_js":"c8d6f7b7","node_modules_prop-types_index_js":"6da256b6","vendors-node_modules_react-ace_lib_index_js":"d476a4bf","vendors-node_modules_react-dom_index_js":"f8dda1f6","vendors-node_modules_react-dropzone_dist_es_index_js":"fc165192",node_modules_react_index_js:"70ac611b",_91571:"42c2d423","node_modules_iobroker_adapter-react-v5_assets_devices_sync_recursive_-node_modules_iobroker_a-de23731":"68986fc3","vendors-node_modules_react-qr-code_lib_index_js":"e61d508f"}[a]+".chunk.js",e.miniCssF=a=>{},e.g=function(){if(typeof globalThis=="object")return globalThis;try{return this||new Function("return this")()}catch(a){if(typeof window=="object")return window}}(),e.o=(a,u)=>Object.prototype.hasOwnProperty.call(a,u),(()=>{var a={},u="iobroker-admin-component-telegram:";e.l=(n,l,v,p)=>{if(a[n]){a[n].push(l);return}var c,x;if(v!==void 0)for(var m=document.getElementsByTagName("script"),k=0;k<m.length;k++){var f=m[k];if(f.getAttribute("src")==n||f.getAttribute("data-webpack")==u+v){c=f;break}}c||(x=!0,c=document.createElement("script"),c.charset="utf-8",c.timeout=120,e.nc&&c.setAttribute("nonce",e.nc),c.setAttribute("data-webpack",u+v),c.src=n),a[n]=[l];var b=(P,y)=>{c.onerror=c.onload=null,clearTimeout(g);var w=a[n];if(delete a[n],c.parentNode&&c.parentNode.removeChild(c),w&&w.forEach(h=>h(y)),P)return P(y)},g=setTimeout(b.bind(null,void 0,{type:"timeout",target:c}),12e4);c.onerror=b.bind(null,c.onerror),c.onload=b.bind(null,c.onload),x&&document.head.appendChild(c)}})(),e.r=a=>{typeof Symbol!="undefined"&&Symbol.toStringTag&&Object.defineProperty(a,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(a,"__esModule",{value:!0})},e.nmd=a=>(a.paths=[],a.children||(a.children=[]),a),(()=>{e.S={};var a={},u={};e.I=(n,l)=>{l||(l=[]);var v=u[n];if(v||(v=u[n]={}),!(l.indexOf(v)>=0)){if(l.push(v),a[n])return a[n];e.o(e.S,n)||(e.S[n]={});var p=e.S[n],c=b=>{typeof console!="undefined"&&console.warn&&console.warn(b)},x="iobroker-admin-component-telegram",m=(b,g,P,y)=>{var w=p[b]=p[b]||{},h=w[g];(!h||!h.loaded&&(!y!=!h.eager?y:x>h.from))&&(w[g]={get:P,from:x,eager:!!y})},k=b=>{var g=h=>c("Initialization of sharing external failed: "+h);try{var P=e(b);if(!P)return;var y=h=>h&&h.init&&h.init(e.S[n],l);if(P.then)return f.push(P.then(y,g));var w=y(P);if(w&&w.then)return f.push(w.catch(g))}catch(h){g(h)}},f=[];switch(n){case"default":m("@iobroker/adapter-react-v5","7.0.1",()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_react-color_es_index_js-node_modules_react-icons_lib_index_mjs"),e.e("vendors-node_modules_mui_material_colors_index_js-node_modules_mui_material_styles_index_js"),e.e("vendors-node_modules_iobroker_adapter-react-v5_index_js-node_modules_mui_material_styles_cssU-325e90"),e.e("webpack_sharing_consume_default_react_react"),e.e("webpack_sharing_consume_default_prop-types_prop-types"),e.e("webpack_sharing_consume_default_mui_icons-material_mui_icons-material-webpack_sharing_consume-6275fc"),e.e("webpack_sharing_consume_default_react-dropzone_react-dropzone"),e.e("node_modules_iobroker_adapter-react-v5_assets_devices_sync_recursive_-node_modules_iobroker_a-de23730")]).then(()=>()=>e(64620))),m("@iobroker/json-config","7.1.0",()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_mui_material_FilledInput_FilledInput_js"),e.e("vendors-node_modules_react-color_es_index_js-node_modules_react-icons_lib_index_mjs"),e.e("vendors-node_modules_iobroker_json-config_build_index_js"),e.e("webpack_sharing_consume_default_react_react"),e.e("webpack_sharing_consume_default_prop-types_prop-types"),e.e("webpack_sharing_consume_default_react-dom_react-dom"),e.e("webpack_sharing_consume_default_mui_icons-material_mui_icons-material-webpack_sharing_consume-6275fc"),e.e("webpack_sharing_consume_default_react-dropzone_react-dropzone"),e.e("webpack_sharing_consume_default_iobroker_adapter-react-v5_iobroker_adapter-react-v5"),e.e("webpack_sharing_consume_default_mui_x-date-pickers_mui_x-date-pickers-webpack_sharing_consume-9f1a2d"),e.e("_91570")]).then(()=>()=>e(93488))),m("@mui/icons-material","6.0.2",()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_mui_icons-material_esm_index_js"),e.e("webpack_sharing_consume_default_react_react"),e.e("webpack_sharing_consume_default_prop-types_prop-types")]).then(()=>()=>e(61636))),m("@mui/material","6.0.2",()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_mui_material_FilledInput_FilledInput_js"),e.e("vendors-node_modules_mui_material_Button_Button_js-node_modules_mui_material_Chip_Chip_js-nod-a86d80"),e.e("vendors-node_modules_mui_material_colors_index_js-node_modules_mui_material_styles_index_js"),e.e("vendors-node_modules_mui_material_index_js"),e.e("webpack_sharing_consume_default_react_react"),e.e("webpack_sharing_consume_default_prop-types_prop-types"),e.e("webpack_sharing_consume_default_react-dom_react-dom")]).then(()=>()=>e(24224))),m("@mui/x-date-pickers","7.16.0",()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_mui_material_FilledInput_FilledInput_js"),e.e("vendors-node_modules_mui_material_Button_Button_js-node_modules_mui_material_Chip_Chip_js-nod-a86d80"),e.e("vendors-node_modules_mui_x-date-pickers_index_js"),e.e("webpack_sharing_consume_default_react_react"),e.e("webpack_sharing_consume_default_prop-types_prop-types"),e.e("webpack_sharing_consume_default_react-dom_react-dom")]).then(()=>()=>e(21412))),m("prop-types","15.8.1",()=>e.e("node_modules_prop-types_index_js").then(()=>()=>e(75826))),m("react-ace","12.0.0",()=>Promise.all([e.e("vendors-node_modules_react-ace_lib_index_js"),e.e("webpack_sharing_consume_default_react_react"),e.e("webpack_sharing_consume_default_prop-types_prop-types")]).then(()=>()=>e(76216))),m("react-dom","18.3.1",()=>Promise.all([e.e("vendors-node_modules_react-dom_index_js"),e.e("webpack_sharing_consume_default_react_react")]).then(()=>()=>e(22483))),m("react-dropzone","14.2.3",()=>Promise.all([e.e("vendors-node_modules_react-dropzone_dist_es_index_js"),e.e("webpack_sharing_consume_default_react_react"),e.e("webpack_sharing_consume_default_prop-types_prop-types")]).then(()=>()=>e(72589))),m("react","18.3.1",()=>e.e("node_modules_react_index_js").then(()=>()=>e(77810)));break}return f.length?a[n]=Promise.all(f).then(()=>a[n]=1):a[n]=1}}})(),(()=>{var a;e.g.importScripts&&(a=e.g.location+"");var u=e.g.document;if(!a&&u&&(u.currentScript&&(a=u.currentScript.src),!a)){var n=u.getElementsByTagName("script");if(n.length)for(var l=n.length-1;l>-1&&(!a||!/^http(s?):/.test(a));)a=n[l--].src}if(!a)throw new Error("Automatic publicPath is not supported in this browser");a=a.replace(/#.*$/,"").replace(/\?.*$/,"").replace(/\/[^\/]+$/,"/"),e.p=a+"../../"})(),(()=>{var a=r=>{var o=s=>s.split(".").map(t=>+t==t?+t:t),_=/^([^-+]+)?(?:-([^+]+))?(?:\+(.+))?$/.exec(r),d=_[1]?o(_[1]):[];return _[2]&&(d.length++,d.push.apply(d,o(_[2]))),_[3]&&(d.push([]),d.push.apply(d,o(_[3]))),d},u=(r,o)=>{r=a(r),o=a(o);for(var _=0;;){if(_>=r.length)return _<o.length&&(typeof o[_])[0]!="u";var d=r[_],s=(typeof d)[0];if(_>=o.length)return s=="u";var t=o[_],i=(typeof t)[0];if(s!=i)return s=="o"&&i=="n"||i=="s"||s=="u";if(s!="o"&&s!="u"&&d!=t)return d<t;_++}},n=r=>{var o=r[0],_="";if(r.length===1)return"*";if(o+.5){_+=o==0?">=":o==-1?"<":o==1?"^":o==2?"~":o>0?"=":"!=";for(var d=1,s=1;s<r.length;s++)d--,_+=(typeof(i=r[s]))[0]=="u"?"-":(d>0?".":"")+(d=2,i);return _}var t=[];for(s=1;s<r.length;s++){var i=r[s];t.push(i===0?"not("+j()+")":i===1?"("+j()+" || "+j()+")":i===2?t.pop()+" "+t.pop():n(i))}return j();function j(){return t.pop().replace(/^\((.+)\)$/,"$1")}},l=(r,o)=>{if(0 in r){o=a(o);var _=r[0],d=_<0;d&&(_=-_-1);for(var s=0,t=1,i=!0;;t++,s++){var j,F,S=t<r.length?(typeof r[t])[0]:"";if(s>=o.length||(F=(typeof(j=o[s]))[0])=="o")return!i||(S=="u"?t>_&&!d:S==""!=d);if(F=="u"){if(!i||S!="u")return!1}else if(i)if(S==F)if(t<=_){if(j!=r[t])return!1}else{if(d?j>r[t]:j<r[t])return!1;j!=r[t]&&(i=!1)}else if(S!="s"&&S!="n"){if(d||t<=_)return!1;i=!1,t--}else{if(t<=_||F<S!=d)return!1;i=!1}else S!="s"&&S!="n"&&(i=!1,t--)}}var D=[],z=D.pop.bind(D);for(s=1;s<r.length;s++){var O=r[s];D.push(O==1?z()|z():O==2?z()&z():O?l(O,o):!z())}return!!z()},v=(r,o)=>r&&e.o(r,o),p=r=>(r.loaded=1,r.get()),c=r=>Object.keys(r).reduce((o,_)=>(r[_].eager&&(o[_]=r[_]),o),{}),x=(r,s,_)=>{var d=_?c(r[s]):r[s],s=Object.keys(d).reduce((t,i)=>!t||u(t,i)?i:t,0);return s&&d[s]},m=(r,t,_,d)=>{var s=d?c(r[t]):r[t],t=Object.keys(s).reduce((i,j)=>l(_,j)&&(!i||u(i,j))?j:i,0);return t&&s[t]},k=(r,o,_)=>{var d=_?c(r[o]):r[o];return Object.keys(d).reduce((s,t)=>!s||!d[s].loaded&&u(s,t)?t:s,0)},f=(r,o,_,d)=>"Unsatisfied version "+_+" from "+(_&&r[o][_].from)+" of shared singleton module "+o+" (required "+n(d)+")",b=(r,o,_,d,s)=>{var t=r[_];return"No satisfying version ("+n(d)+")"+(s?" for eager consumption":"")+" of shared module "+_+" found in shared scope "+o+`.
Available versions: `+Object.keys(t).map(i=>i+" from "+t[i].from).join(", ")},g=r=>{throw new Error(r)},P=(r,o)=>g("Shared module "+o+" doesn't exist in shared scope "+r),y=r=>{typeof console!="undefined"&&console.warn&&console.warn(r)},w=r=>function(o,_,d,s,t){var i=e.I(o);return i&&i.then&&!d?i.then(r.bind(r,o,e.S[o],_,!1,s,t)):r(o,e.S[o],_,d,s,t)},h=(r,o,_)=>_?_():P(r,o),$=w((r,o,_,d,s)=>v(o,_)?p(x(o,_,d)):h(r,_,s)),U=w((r,o,_,d,s,t)=>{if(!v(o,_))return h(r,_,t);var i=m(o,_,s,d);return i?p(i):(y(b(o,r,_,s,d)),p(x(o,_,d)))}),L=w((r,o,_,d,s,t)=>{if(!v(o,_))return h(r,_,t);var i=m(o,_,s,d);if(i)return p(i);if(t)return t();g(b(o,r,_,s,d))}),G=w((r,o,_,d,s)=>{if(!v(o,_))return h(r,_,s);var t=k(o,_,d);return p(o[_][t])}),C=w((r,o,_,d,s,t)=>{if(!v(o,_))return h(r,_,t);var i=k(o,_,d);return l(s,i)||y(f(o,_,i,s)),p(o[_][i])}),H=w((r,o,_,d,s,t)=>{if(!v(o,_))return h(r,_,t);var i=k(o,_,d);return l(s,i)||g(f(o,_,i,s)),p(o[_][i])}),E={},V={28437:()=>C("default","react",!1,[0],()=>e.e("node_modules_react_index_js").then(()=>()=>e(77810))),95973:()=>C("default","prop-types",!1,[0],()=>e.e("node_modules_prop-types_index_js").then(()=>()=>e(75826))),23479:()=>C("default","react-dom",!1,[0],()=>e.e("vendors-node_modules_react-dom_index_js").then(()=>()=>e(22483))),21839:()=>C("default","@mui/icons-material",!1,[0],()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_mui_icons-material_esm_index_js")]).then(()=>()=>e(61636))),67085:()=>C("default","@mui/material",!1,[0],()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_mui_material_FilledInput_FilledInput_js"),e.e("vendors-node_modules_mui_material_Button_Button_js-node_modules_mui_material_Chip_Chip_js-nod-a86d80"),e.e("vendors-node_modules_mui_material_colors_index_js-node_modules_mui_material_styles_index_js"),e.e("vendors-node_modules_mui_material_index_js"),e.e("webpack_sharing_consume_default_react-dom_react-dom")]).then(()=>()=>e(24224))),37449:()=>C("default","@iobroker/adapter-react-v5",!1,[0],()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_react-color_es_index_js-node_modules_react-icons_lib_index_mjs"),e.e("vendors-node_modules_mui_material_colors_index_js-node_modules_mui_material_styles_index_js"),e.e("vendors-node_modules_iobroker_adapter-react-v5_index_js-node_modules_mui_material_styles_cssU-325e90"),e.e("webpack_sharing_consume_default_react-dropzone_react-dropzone"),e.e("node_modules_iobroker_adapter-react-v5_assets_devices_sync_recursive_-node_modules_iobroker_a-de23731")]).then(()=>()=>e(64620))),60556:()=>C("default","@iobroker/json-config",!1,[0],()=>Promise.all([e.e("vendors-node_modules_mui_material_styles_styled_js-node_modules_mui_system_DefaultPropsProvid-85c197"),e.e("vendors-node_modules_mui_material_FilledInput_FilledInput_js"),e.e("vendors-node_modules_react-color_es_index_js-node_modules_react-icons_lib_index_mjs"),e.e("vendors-node_modules_iobroker_json-config_build_index_js"),e.e("webpack_sharing_consume_default_react-dom_react-dom"),e.e("webpack_sharing_consume_default_react-dropzone_react-dropzone"),e.e("webpack_sharing_consume_default_mui_x-date-pickers_mui_x-date-pickers-webpack_sharing_consume-9f1a2d"),e.e("_91571")]).then(()=>()=>e(93488))),53683:()=>C("default","react-dropzone",!1,[0],()=>e.e("vendors-node_modules_react-dropzone_dist_es_index_js").then(()=>()=>e(72589))),28497:()=>C("default","@mui/x-date-pickers",!1,[0],()=>Promise.all([e.e("vendors-node_modules_mui_material_Button_Button_js-node_modules_mui_material_Chip_Chip_js-nod-a86d80"),e.e("vendors-node_modules_mui_x-date-pickers_index_js")]).then(()=>()=>e(21412))),58093:()=>C("default","react-ace",!1,[0],()=>e.e("vendors-node_modules_react-ace_lib_index_js").then(()=>()=>e(76216)))},T={webpack_sharing_consume_default_react_react:[28437],"webpack_sharing_consume_default_prop-types_prop-types":[95973],"webpack_sharing_consume_default_react-dom_react-dom":[23479],"webpack_sharing_consume_default_mui_icons-material_mui_icons-material-webpack_sharing_consume-6275fc":[21839,67085],"webpack_sharing_consume_default_iobroker_adapter-react-v5_iobroker_adapter-react-v5":[37449],src_ConfigCustomInstancesSelector_jsx:[60556],"webpack_sharing_consume_default_react-dropzone_react-dropzone":[53683],"webpack_sharing_consume_default_mui_x-date-pickers_mui_x-date-pickers-webpack_sharing_consume-9f1a2d":[28497,58093]},I={};e.f.consumes=(r,o)=>{e.o(T,r)&&T[r].forEach(_=>{if(e.o(E,_))return o.push(E[_]);if(!I[_]){var d=i=>{E[_]=0,e.m[_]=j=>{delete e.c[_],j.exports=i()}};I[_]=!0;var s=i=>{delete E[_],e.m[_]=j=>{throw delete e.c[_],i}};try{var t=V[_]();t.then?o.push(E[_]=t.then(d).catch(s)):d(t)}catch(i){s(i)}}})}})(),(()=>{var a={main:0};e.f.j=(l,v)=>{var p=e.o(a,l)?a[l]:void 0;if(p!==0)if(p)v.push(p[2]);else if(/^webpack_sharing_consume_default_(mui_(icons\-material_mui_icons\-material\-webpack_sharing_consume\-6275fc|x\-date\-pickers_mui_x\-date\-pickers\-webpack_sharing_consume\-9f1a2d)|react(\-d(om_react\-dom|ropzone_react\-dropzone)|_react)|iobroker_adapter\-react\-v5_iobroker_adapter\-react\-v5|prop\-types_prop\-types)$/.test(l))a[l]=0;else{var c=new Promise((f,b)=>p=a[l]=[f,b]);v.push(p[2]=c);var x=e.p+e.u(l),m=new Error,k=f=>{if(e.o(a,l)&&(p=a[l],p!==0&&(a[l]=void 0),p)){var b=f&&(f.type==="load"?"missing":f.type),g=f&&f.target&&f.target.src;m.message="Loading chunk "+l+` failed.
(`+b+": "+g+")",m.name="ChunkLoadError",m.type=b,m.request=g,p[1](m)}};e.l(x,k,"chunk-"+l,l)}};var u=(l,v)=>{var p=v[0],c=v[1],x=v[2],m,k,f=0;if(p.some(g=>a[g]!==0)){for(m in c)e.o(c,m)&&(e.m[m]=c[m]);if(x)var b=x(e)}for(l&&l(v);f<p.length;f++)k=p[f],e.o(a,k)&&a[k]&&a[k][0](),a[k]=0},n=self.webpackChunkiobroker_admin_component_telegram=self.webpackChunkiobroker_admin_component_telegram||[];n.forEach(u.bind(null,0)),n.push=u.bind(null,n.push.bind(n))})(),e.nc=void 0;var A=e(56046)})();

//# sourceMappingURL=main.43d3359f.js.map