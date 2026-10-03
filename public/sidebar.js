(() => {
  const host = document.getElementById("appSidebar");
  if (!host) return;
  const links = [
    {href:"/", icon:"▥", label:"لوحة العرض"},
    {href:"/employees.html", icon:"♙", label:"الموظفون والإحصائيات"},
    {href:"/settings.html", icon:"⚙", label:"الإعدادات"},
    {href:"/organization.html", icon:"▤", label:"الهيكل التنظيمي"},
    {href:"/planning.html", icon:"◫", label:"التخطيط الوظيفي"},
    {href:"/projects.html", icon:"▣", label:"وظائف المشاريع"}
  ];
  const disabled = [
    {icon:"♙", label:"المستخدمون والصلاحيات"},
    {icon:"◷", label:"الإجازات"},
    {icon:"⚑", label:"العقوبات"},
    {icon:"₪", label:"الرواتب"},
    {icon:"⇧", label:"استيراد الموظفين"},
    {icon:"▤", label:"القدرة والموظفون"}
  ];
  const normalize = value => value.length > 1 && value.endsWith("/") ? value.slice(0, -1) : value;
  const path = normalize(location.pathname) || "/";
  const linkMarkup = links.map(item => {
    const target = normalize(item.href) || "/";
    const active = path === target;
    return '<a href="' + item.href + '" class="app-nav-link' + (active ? ' active' : '') + '"' + (active ? ' aria-current="page"' : '') + '><span class="app-icon" aria-hidden="true">' + item.icon + '</span><span>' + item.label + '</span></a>';
  }).join("");
  const disabledMarkup = disabled.map(item => '<a href="#" class="app-nav-link disabled" aria-disabled="true" tabindex="-1"><span class="app-icon" aria-hidden="true">' + item.icon + '</span><span>' + item.label + '</span></a>').join("");
  host.innerHTML = '<div class="app-side-brand"><span class="app-side-mark" aria-hidden="true">✚</span><div><strong>جمعية الهلال الأحمر الفلسطيني</strong><small>نظام إدارة شؤون الموظفين</small></div></div><div class="app-caption">القائمة الرئيسية</div><nav class="app-nav" aria-label="القائمة الرئيسية">' + linkMarkup + '</nav><div class="app-divider"></div><div class="app-caption">إدارة الموارد البشرية</div><nav class="app-nav" aria-label="إدارة الموارد البشرية">' + disabledMarkup + '</nav><div class="app-side-foot">الهلال الأحمر الفلسطيني © 2026</div>';
})();
