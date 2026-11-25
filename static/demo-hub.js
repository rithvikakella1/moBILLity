(async()=>{
  const user=await window.demoAccess;
  if(!user)return;
  document.querySelector('#demoAccount').textContent=user.full_name||user.email;
  const sources={coder:'app.html?embedded=1',workflow:'workflows.html?demo=1&embedded=1',patient:'patient.html?embedded=1'};
  const tabs=[...document.querySelectorAll('[data-tab]')];
  function activate(name){
    if(!Object.hasOwn(sources,name))name='coder';
    tabs.forEach(tab=>{const selected=tab.dataset.tab===name;if(!selected)document.querySelector(`#frame-${tab.dataset.tab}`).contentWindow?.postMessage({type:'mobillity:demo-hidden'},location.origin);tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;document.querySelector(`#panel-${tab.dataset.tab}`).hidden=!selected;});
    const frame=document.querySelector(`#frame-${name}`);
    if(!frame.getAttribute('src'))frame.src=sources[name];
    history.replaceState(null,'',`?tab=${name}`);
  }
  tabs.forEach((tab,index)=>{
    tab.addEventListener('click',()=>activate(tab.dataset.tab));
    tab.addEventListener('keydown',event=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();const next=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[next].focus();activate(tabs[next].dataset.tab);});
  });
  document.querySelector('#demoLogout').addEventListener('click',async()=>{
    document.querySelector('#demoLogout').disabled=true;
    try{
      const csrf=decodeURIComponent(document.cookie.split('; ').find(row=>row.startsWith('mobillity_csrf='))?.split('=')[1]||'');
      const response=await fetch('/api/logout',{method:'POST',headers:{'X-CSRF-Token':csrf},credentials:'same-origin'});
      if(!response.ok)throw new Error();
      document.body.dataset.authState='checking';
      document.querySelectorAll('iframe').forEach(frame=>frame.src='about:blank');
      location.replace('/login.html');
    }catch{document.querySelector('#demoLogout').disabled=false;document.querySelector('#demoAccount').textContent='Sign-out failed. Please try again.';}
  });
  activate(new URLSearchParams(location.search).get('tab')||'coder');
})();
