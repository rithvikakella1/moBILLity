/* Shared, fail-closed access check. Query parameters never bypass authentication. */
(() => {
  const tabs=['coder','workflow','patient'];
  const file=location.pathname.split('/').pop().replace('.html','');
  const tab=({app:'coder',workflows:'workflow',patient:'patient'})[file]||new URLSearchParams(location.search).get('tab')||'coder';
  const target=tabs.includes(tab)?tab:'coder';
  const login=`/login.html?tab=${target}`;
  if(new URLSearchParams(location.search).get('embedded')==='1'&&window.self!==window.top)document.documentElement.classList.add('embedded-demo');
  function lock(){document.body.dataset.authState='checking';}
  window.demoAccess=(async()=>{
    try{
      const response=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});
      if(!response.ok)throw new Error('Sign-in required');
      const user=await response.json();
      if(!user||typeof user.email!=='string')throw new Error('Invalid session');
      document.body.dataset.authState='ready';
      return user;
    }catch{
      lock();
      if(window.self!==window.top)window.top.location.replace(login);
      else location.replace(login);
      return null;
    }
  })();
  // A cached page must revalidate before exposing a restored demo.
  window.addEventListener('pageshow',event=>{if(event.persisted){lock();location.reload();}});
  async function revalidate(){
    try{const response=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});if(!response.ok)throw new Error();}
    catch{lock();if(window.self!==window.top)window.top.location.replace(login);else location.replace(login);}
  }
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')revalidate();});
  setInterval(()=>{if(document.visibilityState==='visible')revalidate();},60000);
})();
