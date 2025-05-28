from django.urls import path
from admin_app import views
from django.utils.translation import gettext_lazy as _
urlpatterns = [
    path("home/", views.homePage, name="home"),
    # log Management
    path("sendlogmanagement/", views.LogManagement.as_view(), name="logmanagement"),
    #Capture log Management
    path("download-capture-info/",views.CaptureLogManagement.as_view(),name="capturelogmanagement"),
    # Authentication
    path("login/", views.login_view, name="login"),
    path("logout/", views.logoutView, name="logout"),
    path("unauthorized/", views.UnauthorizedView, name="unauthorized"),
    # CommonManagement
    path("code-management/", views.code_management, name="code_management"),
    path("menu-management/", views.menu_management, name="menu_management"),
    path("permission-management/",views.permission_management,name="permission_management",),
    # UserManagement
    path("user-management/", views.user_management, name="user_management"),
    path("user-management-list/", views.user_management_list, name="user_management_list"),
    path("user-management-register/",views.user_management_register,name="user_management_register"),
    # Calling the edit user page from admin panel
    path( "user-management-update/<int:pk>/",views.user_management_edit,name="user_management_update",),
    # Updating from admin panel
    path("usermanagement-update/",views.usermanagement_update,name="usermanagement_update"),
    path("delete_user_management_user/<int:pk>",views.delete_user_management_user,name="delete_user_management_user",),
    # CommunityManagement
    path("notice/", views.notice, name="notice"),
    path("notice-list/", views.notice_list, name="notice_list"),
    path("notice-add/", views.notice_form, name="notice_create"),
    path("notice-update/<int:pk>/", views.edit_notice_form, name="notice_update"),
    path("notice-delete/<int:pk>/", views.delete_notice_form, name="notice_delete"),
    path("q_and_a/", views.q_and_a, name="q_and_a"),
    path("q_and_a_list/", views.q_and_a_list, name="q_and_a_list"),
    path("q_and_a-add/", views.q_and_a_form, name="q_and_a_create"),
    path("q_and_a-update/<int:pk>/", views.edit_q_and_a_form, name="q_and_a_update"),
    path("q_and_a-delete/<int:pk>/", views.delete_q_and_a_form, name="q_and_a_delete"),
    path("faq/", views.faq, name="faq"),
    path("faq-list/", views.faq_list, name="faq_list"),
    path("faq-add/", views.faq_form, name="faq_form"),
    path("faq-update/<int:pk>/", views.edit_faq_form, name="faq_update"),
    path("faq_delete/<int:pk>/", views.delete_faq_form, name="faq_delete"),
    # Opertaion Management
    path("bulletin/", views.bulletin, name="bulletin"),
    path("bulletin-create/", views.bulletin_create, name="bulletin_create"),
    # DataApplicationManagement
    path("data-application-list/", views.data_application, name="data_application"),
    # ServiceManagement
    path("openapi/", views.openapi, name="openapi"),
    # Log
    path("log-list/", views.log_list, name="log_list"),
    path("log-data/", views.log_data, name="log_data"),
    path("capture-log-list/", views.capture_log_list, name="capture_log_list"),
    path("capture-log-data/", views.capture_log_data, name="capture_log_data"),
    # API's
    # FAQ APIV
    path("faq-api/", views.FaqApi.as_view(), name="faq_api"),
    # Notice API
    path("notice-api/", views.NoticeApi.as_view(), name="notice_api"),
    # Q and A API
    path("qa-api/", views.QA_Api.as_view(), name="qa_api"),
    # google Analytics
    path("google-analytics/", views.google_analytics_dashboard, name="google_analytics"),
    path("check-user-id/", views.check_user_id, name="check_user_id"),
    # path("count-page/", views.CountPage.as_view(), name="count-page"),
    #Project Management
    path("project_list/", views.project_list, name="project_list"),
    path("project_data/", views.project_data, name="project_data"),
    path("change-password/<int:pk>/", views.change_password, name="change_password"),
    path('session-stats/', views.get_session_stats, name='session_stats'),
    path('session_mgmt/', views.session_management_view, name='session_mgmt'),
    path('analysis-stats/', views.analysis_stats_view, name='analysis_stats_view'),
]
