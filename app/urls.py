from django.urls import path
from app.views import *
urlpatterns = [
    # csrf token
    path("csrf-token/", GetCSRFToken.as_view(), name="csrf_token"),
    path("logout/", LogoutView.as_view(), name="logout_view"),
    path("session-check/", IsSessionandSessionData.as_view(), name="session_check"),
    # Registration, Login, Passwords
    path("api/token/", Login.as_view(), name="token_obtain_pair"),
    path("new-registration/", NewRegistration.as_view(), name="new_registration"),
    path("set-password/", ChangePassword.as_view(), name="set_password"),
    path("change-password/", ChangePassword.as_view(), name="change_password"),
    path("findid/", FindID.as_view(), name="findid"),
    path("findpassword/", FindPassword.as_view(), name="findpassword"),
    # home Page
    path("notice-popup/", NoticeApi.as_view(), name="noticepopup"),
    # # DataSummary Page
    # path("data-summary/", DataSummaryList.as_view()),
    path("gene-info/", GeneInfo.as_view(), name="geneinfo"),

    ######## All Charts Visualisation ########
    path("circos/", CircosPlot.as_view()),
    path("oncoprint/", OncoPrintPlot.as_view()),
    # Fusion
    path("getFusionVenn/", FusionVenn.as_view()),
    path("fusion-plot/", FusionPlot.as_view()),
    path("getFusionExons/", FusionExons.as_view()),

    path("heatmap/", HeatMapPlot.as_view(), name="heatmap"),
    path("lollipop/", LollipopPlot.as_view(), name="lollipop"),
    path("survival/", SurvivalPlot.as_view(), name="survival"),
    path("scatter-plot/", ScatterPlot.as_view()),
    path("pca-plot/", PcaPlot.as_view()),
    path("igv/", IgvViewPlot.as_view()),
    path("box-plot/", BoxPlot.as_view()),
    path("volcano/", VolcanoPlot.as_view(), name="volcano"),

    path("brst-key/", BrstRelations.as_view(), name="brst-key"),
    path("samplescount/", GetSamplesCount.as_view(), name="samplecount"),
    path("getClinicalMaxMinInfo/", ClinicalMaxMinInfo.as_view()),
    # Other Visualisation Api's
    path("report/", Report.as_view(), name="rnidetails"),
    path("sankeyimagedata/", SankeyImageData, name="sankeyimagedata"),
    path("getSankeyJson/", SankeyJson.as_view()),
    path("generatereport/", generateReport, name="generatereport"),
    # Tools
    path("interpro/", InterproFile.as_view(), name="interpro"),
    path("vcfmaf/", VcfMaf.as_view(), name="vcfmaf"),
    path("mafmerger/", MafMerger.as_view(), name="mafmerger"),
    path("refverconverter/", REFVERCONVERTER.as_view(), name="refverconverter"),
    path("blast/", Blast.as_view(), name="blast"),
    path("dfrecon/", MatrixToMelted.as_view(), name="df_reconstruction"),
]
