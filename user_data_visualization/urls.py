from django.urls import path
from .views import *

urlpatterns = [
    # Used to get the filter data in frontend
    path(
        "new-user-data-visualization_filter/",
        FilterJson.as_view(),
        name="new-user-data-filter-json",
    ),
    # Used to see the user details for particular Project id
    path(
        "user-data-projects/<str:project_id>/",
        UserDataVisualizationProjects.as_view(),
        name="user-project-table",
    ),
    path(
        "user-data-projects/",
        UserDataVisualizationProjects.as_view(),
        name="user-project-table",
    ),
    path("user-project-table/", UserProjectFilesDataTable.as_view()),
    path("user-projects-data/", UserDataExtensionProjectsDetails.as_view()),
    #We bring data from UserDataExtension table to the frontend now
    # checking the count
    path("user-projects-data-count/", UserDataVisualizationProjectsCount.as_view()),
    # deleting the project
    path(
        "delete-user-project-data/<str:project_id>/",
        UserDataVisualizationProjectsDelete.as_view(),
    ),
    path(
        "extend-user-project-data/<str:project_id>/",
        UserDataProjectsExtend.as_view(),
    ),
    # uploading Files
    path(
        "new-user-data-visualization/",
        NewUserDataVisualization.as_view(),
        name="new-user-data",
    ),
    # multi uploading Files
    path(
        "single-new-user-data-visualization/",
        NewUserDataVisualization.as_view(),
        name="single-user-data",
    ),
    # multi uploading Files
    path(
        "multi-new-user-data-visualization/",
        NewUserDataVisualization.as_view(),
        name="multi-user-data",
    ),
    # path(
    #     "multi-new-user-data-visualization/",
    #     UploadFilesView.as_view(),
    #     name="multi-user-data",
    # ),
    # Reading Files
    path(
        "upload-clinical-columns/",
        VerifyClinicalDataColumns.as_view(),
        name="upload-clinical-columns",
    ),
    # Creating Shared Hg38
    path("created-shared-db/", CreateSharedDB.as_view(), name="shared-db"),
    # Reading Files
    path(
        "delete-directory/",
        DeleteDirectoryContentsAPIView.as_view(),
        name="delete-directory",
    ),

    #New
    # path(
    #     "upload-files/",
    #     UploadFilesView.as_view(),
    #     name="upload-files",
    # ),
    # path(
    #     "check_project_status/<str:project_id>/",
    #     check_project_status,
    #     name= "check_project_status"
    # ),
]
