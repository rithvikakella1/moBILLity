(() => {
  const root=document.getElementById('demoDropdown');
  const trigger=document.getElementById('demoTrigger');
  const menu=document.getElementById('demoMenu');
  if(!root||!trigger||!menu)return;
  const links=[...menu.querySelectorAll('a')];
  const hover=matchMedia('(hover: hover)');
  let clickOpen=false;
  function setOpen(open){menu.hidden=!open;trigger.setAttribute('aria-expanded',String(open));}
  trigger.addEventListener('click',()=>{clickOpen=!clickOpen;setOpen(clickOpen);});
  root.addEventListener('pointerenter',()=>{if(hover.matches)setOpen(true);});
  root.addEventListener('pointerleave',()=>{if(hover.matches&&!clickOpen&&!root.contains(document.activeElement))setOpen(false);});
  root.addEventListener('focusout',event=>{if(!root.contains(event.relatedTarget)){clickOpen=false;setOpen(false);}});
  document.addEventListener('pointerdown',event=>{if(!root.contains(event.target)){clickOpen=false;setOpen(false);}});
  root.addEventListener('keydown',event=>{
    if(event.key==='Escape'){event.preventDefault();clickOpen=false;setOpen(false);trigger.focus();return;}
    if(!['ArrowDown','ArrowUp','Home','End'].includes(event.key))return;
    event.preventDefault();setOpen(true);
    const current=links.indexOf(document.activeElement);
    const index=event.key==='Home'?0:event.key==='End'?links.length-1:event.key==='ArrowUp'?(current<=0?links.length-1:current-1):(current+1)%links.length;
    links[index].focus();
  });
  links.forEach(link=>link.addEventListener('click',()=>{clickOpen=false;setOpen(false);}));
  document.querySelectorAll('[data-demo-launch]').forEach(button=>button.addEventListener('click',()=>{clickOpen=true;setOpen(true);trigger.focus();}));
})();
