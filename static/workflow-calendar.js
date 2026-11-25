(() => {
  const $ = s => document.querySelector(s);
  const escape = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const demo = new URLSearchParams(location.search).has('demo');
  const dateKey = d => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const addDays = (date,n) => { const d=new Date(date);d.setDate(d.getDate()+n);return d; };
  const midnight = d => new Date(d.getFullYear(),d.getMonth(),d.getDate());
  const time = d => new Date(d).toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});
  const status = a => a.no_show?'no_show':a.status;
  const statusLabel = a => status(a).replace('_',' ');
  let selected=midnight(new Date()),view=innerWidth<700?'day':'week',activeVisit=null;
  // Explicit, isolated design preview. These fictional appointments never reach the API.
  const examples = [];
  if(demo) {
    const names=['Alex Morgan','Jamie Rivera','Taylor Chen','Sam Patel','Casey Brooks','Jordan Lee'];
    for(let offset=-7;offset<15;offset++) for(let n=0;n<4;n++) {
      const d=addDays(midnight(new Date()),offset);d.setHours(8+n*2,n%2?30:0);
      examples.push({id:`demo-${offset}-${n}`,patient_name:names[(offset+7+n)%names.length],starts_at:d.toISOString(),clinician:n%2?'Dr. Avery Williams':'Dr. Riley Bennett',location:n%2?'Room 204':'Room 102',status:offset<0?'completed':n%2?'confirmed':'scheduled',no_show:false});
    }
    const missed=examples.find(a=>dateKey(new Date(a.starts_at))===dateKey(addDays(new Date(),-1)));if(missed){missed.status='scheduled';missed.no_show=true;}
    $('#patientCount').textContent=names.length;$('#appointmentCount').textContent=examples.filter(a=>new Date(a.starts_at)>=new Date()&&!a.no_show).length;$('#noShowCount').textContent=examples.filter(a=>a.no_show).length;
    $('#username').textContent='Design preview';$('#deliveryMode').textContent='Demo · fictional patient data · changes are not saved';
  }
  const appointments=()=>demo?examples:window.workflowData.get().appointments;
  function period() {
    if(view==='month')return [new Date(selected.getFullYear(),selected.getMonth(),1),new Date(selected.getFullYear(),selected.getMonth()+1,1)];
    const start=view==='week'?addDays(selected,-selected.getDay()):midnight(selected);
    return [start,addDays(start,view==='week'?7:1)];
  }
  function filtered() {
    const clinician=$('#calendarClinician').value,attendance=$('#calendarStatus').value;
    return appointments().filter(a=>(!clinician||a.clinician===clinician)&&(attendance!=='no_show'||a.no_show)).sort((a,b)=>new Date(a.starts_at)-new Date(b.starts_at));
  }
  function event(a,compact=false) {
    return `<button type="button" class="calendar-event ${escape(status(a))}${compact?' compact':''}" data-visit="${escape(a.id)}" aria-label="${escape(`${a.patient_name}, ${time(a.starts_at)}, ${a.clinician||'Unassigned'}, ${statusLabel(a)}`)}"><span class="event-time">${escape(time(a.starts_at))}</span><strong>${escape(a.patient_name)}</strong>${compact?'':`<span>${escape(a.clinician||'Unassigned clinician')}</span><span class="event-status">${escape(statusLabel(a))}</span>`}</button>`;
  }
  function renderCalendar() {
    const clinician=$('#calendarClinician'),old=clinician.value;
    const clinicians=[...new Set(appointments().map(a=>a.clinician).filter(Boolean))].sort();
    clinician.innerHTML='<option value="">All clinicians</option>'+clinicians.map(c=>`<option value="${escape(c)}">${escape(c)}</option>`).join('');clinician.value=clinicians.includes(old)?old:'';
    const [start,end]=period(),all=filtered(),visible=all.filter(a=>new Date(a.starts_at)>=start&&new Date(a.starts_at)<end);
    $('#calendarTitle').textContent=view==='month'?selected.toLocaleDateString([],{month:'long',year:'numeric'}):view==='day'?selected.toLocaleDateString([],{weekday:'long',month:'short',day:'numeric',year:'numeric'}):`${start.toLocaleDateString([],{month:'short',day:'numeric'})} – ${addDays(end,-1).toLocaleDateString([],{month:'short',day:'numeric',year:'numeric'})}`;
    $('#calendarSummary').textContent=`${visible.length} appointment${visible.length===1?'':'s'} · ${visible.filter(a=>a.no_show).length} no-show${visible.filter(a=>a.no_show).length===1?'':'s'}`;
    $('#calendarTimezone').textContent=`${Intl.DateTimeFormat().resolvedOptions().timeZone} · Visits displayed by start time; durations are not recorded.`;
    document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.view===view)));
    if(view==='month')renderMonth(start,all);else renderTime(start,visible);
  }
  function renderMonth(start,all) {
    const first=addDays(start,-start.getDay()),days=Array.from({length:42},(_,i)=>addDays(first,i));
    $('#calendarGrid').innerHTML=`<div class="month-weekdays">${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d=>`<span>${d}</span>`).join('')}</div><div class="month-grid">${days.map(d=>{
      const dayEvents=all.filter(a=>dateKey(new Date(a.starts_at))===dateKey(d));
      return `<div class="month-day${d.getMonth()!==selected.getMonth()?' outside':''}${dateKey(d)===dateKey(new Date())?' is-today':''}"><button class="day-number" data-date="${dateKey(d)}" aria-label="Open ${escape(d.toLocaleDateString([],{dateStyle:'full'}))}">${d.getDate()}</button>${dayEvents.slice(0,3).map(a=>event(a,true)).join('')}${dayEvents.length>3?`<button class="more-events" data-date="${dateKey(d)}">+${dayEvents.length-3} more</button>`:''}</div>`;
    }).join('')}</div>`;
  }
  function renderTime(start,items) {
    const days=Array.from({length:view==='week'?7:1},(_,i)=>addDays(start,i));
    const previousScroll=$('#calendarGrid .time-scroll')?.scrollTop;
    $('#calendarGrid').innerHTML=`<div class="time-scroll"><div class="time-grid ${view}"><div class="time-heading"><span class="time-gutter">TIME</span>${days.map(d=>`<button class="date-heading ${dateKey(d)===dateKey(new Date())?'is-today':''}" data-date="${dateKey(d)}"><span>${d.toLocaleDateString([],{weekday:'short'})}</span><strong>${d.getDate()}</strong></button>`).join('')}</div>${Array.from({length:24},(_,hour)=>`<div class="time-row"><span class="time-gutter">${new Date(2000,0,1,hour).toLocaleTimeString([],{hour:'numeric'})}</span>${days.map(d=>`<div class="time-cell">${items.filter(a=>{const t=new Date(a.starts_at);return dateKey(t)===dateKey(d)&&t.getHours()===hour;}).map(a=>event(a)).join('')}</div>`).join('')}</div>`).join('')}</div></div>${items.length?'':'<p class="calendar-empty">No appointments in this period. Use “Schedule a visit” to add one.</p>'}`;
    $('#calendarGrid .time-scroll').scrollTop=previousScroll??7*76;
  }
  function openVisit(id) {
    activeVisit=appointments().find(a=>String(a.id)===String(id));if(!activeVisit)return;
    const a=activeVisit;$('#visitTitle').textContent=a.patient_name;
    $('#visitDetails').innerHTML=`<span class="calendar-detail-status ${escape(status(a))}">${escape(statusLabel(a))}</span><dl><dt>When</dt><dd>${escape(new Date(a.starts_at).toLocaleString([],{dateStyle:'full',timeStyle:'short'}))}</dd><dt>Clinician</dt><dd>${escape(a.clinician||'Unassigned')}</dd><dt>Location</dt><dd>${escape(a.location||'Not specified')}</dd></dl>`;
    const eligible=['scheduled','confirmed'].includes(a.status)&&new Date(a.starts_at)<=new Date();
    $('#visitActions').innerHTML=a.no_show?'<button id="attendanceAction" data-no-show="false" class="calendar-primary">Clear no-show</button>':eligible?'<button id="attendanceAction" data-no-show="true" class="no-show-action">Mark as no-show</button>':'<p class="sub">No-shows can be recorded after an active appointment’s start time.</p>';
    $('#visitFeedback').textContent='';if(!$('#visitDialog').open)$('#visitDialog').showModal();
  }
  $('#visitActions').addEventListener('click',async e=>{
    const button=e.target.closest('#attendanceAction');if(!button||!activeVisit)return;
    if(demo){$('#visitFeedback').textContent='Design preview only. Attendance changes are not saved.';return;}
    const no_show=button.dataset.noShow==='true';button.disabled=true;
    try{await window.workflowData.api(`/api/workflows/appointments/${activeVisit.id}/attendance`,{method:'PATCH',body:JSON.stringify({no_show})});await window.workflowData.load();openVisit(activeVisit.id);$('#visitFeedback').textContent=no_show?'No-show recorded. Pending reminders cancelled.':'No-show cleared. Cancelled reminders remain cancelled.';}catch(err){$('#visitFeedback').textContent=err.message;button.disabled=false;}
  });
  $('#calendarGrid').addEventListener('click',e=>{
    const visit=e.target.closest('[data-visit]');if(visit){openVisit(visit.dataset.visit);return;}
    const date=e.target.closest('[data-date]');if(date){selected=new Date(`${date.dataset.date}T00:00:00`);view='day';renderCalendar();}
  });
  document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>{view=b.dataset.view;renderCalendar();}));
  function move(direction){if(view==='month')selected=new Date(selected.getFullYear(),selected.getMonth()+direction,1);else selected=addDays(selected,direction*(view==='week'?7:1));renderCalendar();}
  $('#previous').onclick=()=>move(-1);$('#next').onclick=()=>move(1);$('#today').onclick=()=>{selected=midnight(new Date());renderCalendar();};
  $('#calendarClinician').onchange=renderCalendar;$('#calendarStatus').onchange=renderCalendar;
  $('#newVisit').onclick=()=>{document.querySelector('#appointmentForm').scrollIntoView({behavior:'smooth',block:'center'});$('#patient').focus({preventScroll:true});};
  if(demo){document.querySelectorAll('#patientForm button,#appointmentForm button,.logout').forEach(b=>b.disabled=true);$('#newVisit').disabled=true;}
  window.renderCalendar=renderCalendar;
  renderCalendar();
})();
