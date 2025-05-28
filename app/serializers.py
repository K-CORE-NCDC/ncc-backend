from app.models import *
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # token['first_name'] = user.first_name
        # token['last_name'] = user.last_name
        token["username"] = user.username
        token["is_superuser"] = user.is_superuser
        return token


class commonSerializer(serializers.Serializer):
    name = serializers.CharField()
    cnt = serializers.IntegerField()


class vc_summary_serializer(serializers.Serializer):
    label = serializers.CharField()
    data = serializers.ListField()


class dnamutationSerializer(serializers.Serializer):
    name = serializers.CharField()
    cnt = serializers.IntegerField()


class dnamutationGeneMutation(serializers.Serializer):
    labels = serializers.CharField()
    vc = serializers.ListField()
    count = serializers.ListField()


class circosSerializer(serializers.Serializer):
    chromosome = serializers.CharField()
    start = serializers.IntegerField(source="chromosome_start")
    end = serializers.IntegerField(source="chromosome_end")
    hugo_symbol = serializers.CharField()
    value = serializers.CharField(source="gc_content")


class OncoSerializer(serializers.Serializer):
    gene = serializers.CharField()
    type = serializers.CharField()
    sample = serializers.CharField()
    alteration = serializers.CharField()


class FileUplodSerializer(serializers.Serializer):
    file = serializers.FileField()
    type = serializers.CharField()
    div_name = serializers.CharField()


class BrstRelationsSerializer(serializers.Serializer):
    rn_key = serializers.CharField()
    brst_key = serializers.CharField()


class VolcanoSerializer(serializers.Serializer):
    gene = serializers.CharField()
    q_value = serializers.FloatField()
    color = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["log2(fold_change)"] = serializers.CharField()


class filter_serializer(serializers.Serializer):
    genes = serializers.ListField(default=[])
    filters = serializers.CharField(default="")
    tab_type = serializers.CharField(default="")


class variant_per_sample_serializer(serializers.Serializer):
    count = serializers.IntegerField()
    label = serializers.CharField()
    vc = serializers.CharField()


class RnaZScoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rna
        fields = "__all__"


class CnvSerializer(serializers.Serializer):
    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #     self.fields['Chromosome'] = serializers.CharField()
    # chr = serializers.CharField(source='chromosome')
    chr = serializers.SerializerMethodField()
    gene = serializers.CharField()
    start = serializers.IntegerField(source="start_pos")
    end = serializers.IntegerField(source="end_pos")
    Num_Probes = serializers.IntegerField(source="probes")
    sample = serializers.CharField()
    value = serializers.FloatField(source="log2")

    def get_chr(self, obj):
        return obj.chromosome.replace("chr", "")


class MutationLollipopSerializer(serializers.Serializer):
    sample = serializers.CharField(source="tumor_sample_barcode")
    gene = serializers.CharField(source="hugo_symbol")
    protien = serializers.CharField(source="protein_change")
    variant_classification = serializers.CharField()
    annotation_transcript = serializers.CharField()
    refseq_mrna_id = serializers.CharField()


class PhospoLollipopSerializer(serializers.Serializer):
    sample = serializers.CharField(source="tumor_sample_barcode")
    gene = serializers.CharField(source="hugo_symbol")
    site = serializers.CharField()


class LollipopDomainSerializer(serializers.Serializer):
    start = serializers.IntegerField(source="start_codon")
    end = serializers.IntegerField(source="end_codon")
    domain = serializers.CharField()


class GlobalProteomeSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    tumor_sample_barcode = serializers.CharField()
    gc_content = serializers.FloatField()
    chromosome = serializers.CharField()
    hugo_symbol = serializers.CharField()
    chromosome_start = serializers.IntegerField()
    chromosome_end = serializers.IntegerField()


class VolcanoPlotSerializer(serializers.Serializer):
    name = serializers.CharField()
    z_score = serializers.FloatField()


class ASDF(circosSerializer):
    default = serializers.SerializerMethodField("get_default")

    def default(self):
        return 1000


class FusionVennRnidSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    left_gene_name = serializers.CharField()
    left_gene_ensmbl_id = serializers.CharField()
    left_gene_chr = serializers.CharField()
    right_gene_name = serializers.CharField()
    right_gene_ensmbl_id = serializers.CharField()
    right_gene_chr = serializers.CharField()


class DnamethylationSerializer(serializers.Serializer):
    hugo_symbol = serializers.CharField()
    target_id = serializers.CharField()
    target_type = serializers.CharField()
    gene_value = serializers.FloatField()
    chromosome = serializers.CharField()
    start_position = serializers.SerializerMethodField()
    end_position = serializers.SerializerMethodField()

    def get_start_position(self, obj):
        return 949000

    def get_end_position(self, obj):
        return 949100


class HeatMapSerializer(serializers.Serializer):

    gene_name = serializers.SerializerMethodField()
    pt_sbst_no = serializers.CharField()
    gene_vl = serializers.FloatField()
    sex_cd = serializers.CharField(required=False)
    diag_age = serializers.CharField(required=False)
    bmi_vl = serializers.CharField(required=False)
    bila_cncr_yn = serializers.CharField(required=False)
    smok_curr_yn = serializers.SerializerMethodField()
    # smok_yn = serializers.CharField(required=False)
    drnk_yn = serializers.CharField(required=False)
    fmhs_brst_yn = serializers.CharField(required=False)
    mena_age = serializers.CharField(required=False)
    meno_yn = serializers.CharField(required=False)
    delv_yn = serializers.CharField(required=False)
    feed_yn = serializers.CharField(required=False)
    feed_drtn_mnth = serializers.CharField(required=False)
    oc_yn = serializers.CharField(required=False)
    hrt_yn = serializers.CharField(required=False)
    t_category = serializers.CharField(required=False)
    n_category = serializers.CharField(required=False)
    her2_score = serializers.CharField(required=False)
    ki67_score = serializers.CharField(required=False)
    rlps_cnfr_drtn = serializers.CharField(required=False)
    rlps_yn = serializers.CharField(required=False)

    def get_gene_name(self, obj):
        try:
            return "{}_{}".format(obj.gene_name, obj.site)
        except:
            return obj.gene_name

    def get_smok_curr_yn(self, obj):
        try:
            if obj.smok_curr_yn == "Y":
                return "Current Smoking"
            elif obj.smok_yn == "Y":
                return "Past Smoking"
            else:
                return "No Smoking"
        except:
            pass


class HeatMapCustomSerializer(serializers.Serializer):
    gene_name = serializers.SerializerMethodField()
    pt_sbst_no = serializers.CharField()
    gene_vl = serializers.FloatField()

    def __init__(self, *args, **kwargs):
        super(HeatMapCustomSerializer, self).__init__(*args, **kwargs)
        # Get the parameters from the serializer context
        dynamic_fields = self.context.get("dynamic_fields", [])
        # Add a serializer field for each dynamic field
        for field_name in dynamic_fields:
            self.fields[field_name] = serializers.CharField(required=False)

    def get_gene_name(self, obj):
        try:
            return "{}_{}".format(obj.gene_name, obj.site)
        except:
            return obj.gene_name


class FilterMergedSerializer(serializers.Serializer):
    pt_sbst_no = serializers.CharField()
    rlps_cnfr_drtn = serializers.FloatField()
    rlps_yn = serializers.BooleanField()
    rlps_yn_data = serializers.IntegerField()


class OncoprintRnaSerializer(serializers.Serializer):
    variant_classification = serializers.CharField()
    sample = serializers.CharField()
    regulation = serializers.CharField()


class RnidYbcBrstKeyRelationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RnidDetails
        fields = ["rn_key", "brst_key"]


class ScatterPlotSerializer(serializers.Serializer):
    x = serializers.FloatField()
    y = serializers.FloatField()
    gene = serializers.CharField()


class VennDiagramSerializer(serializers.Serializer):
    pt_sbst_no = serializers.CharField()


class SurvivalPlotSerializer(serializers.Serializer):
    pt_sbst_no = serializers.CharField()
    rlps_cnfr_drtn = serializers.FloatField()
    rlps_yn = serializers.BooleanField()
    diag_age = serializers.IntegerField()
    sex_cd = serializers.CharField()


class OnoImageSerializer(serializers.Serializer):
    sample_id = serializers.CharField()
    page_no = serializers.IntegerField()


class OnoImageModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = OncoSampleImagesInfo
        fields = "__all__"


class BoxPlotSerializer(serializers.Serializer):
    Sepal_Length = serializers.FloatField(source="y")
    Species = serializers.CharField(source="gene")
    Sample = serializers.CharField(source="pt_sbst_no")
    type = serializers.CharField()


class FusionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Fusion
        fields = "__all__"


class ClinicalInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClinicalInformation
        exclude = (
            "rnid_id",
            "rnid",
        )


class CircosSvFilterSerializer(serializers.Serializer):
    left_gene_chr = serializers.CharField()
    left_gene_name = serializers.CharField()
    left_gene_pos = serializers.IntegerField()
    right_gene_chr = serializers.CharField()
    right_gene_name = serializers.CharField()
    right_gene_pos = serializers.IntegerField()
    svtype = serializers.CharField()


class circosSerializerCnv(serializers.Serializer):
    chromosome = serializers.CharField()
    start_position = serializers.IntegerField()
    end_position = serializers.IntegerField()
    hugo_symbol = serializers.CharField()
    genome_change = serializers.CharField()


class bmiSerializer(serializers.Serializer):
    # rgst_ymd = serializers.DateField()
    bmi_vl = serializers.FloatField()


class ki67Serializer(serializers.Serializer):
    # imnl_read_ymd = serializers.DateField()
    imnl_acpt_ymd = serializers.DateField()
    ki67_score = serializers.CharField()


class FollowupSerializer(serializers.Serializer):
    exam_ymd = serializers.DateField()
    exam_val = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    user_id = serializers.CharField(source='user_id_app')

    class Meta:
        model = User
        fields = "__all__"


class DownloadVisualizationSerializer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField(source='id_down')
    project_id = serializers.ReadOnlyField(source='project_id_app')
    class Meta:
        model = DownloadVisualization
        fields = (
            "id",          # alias of id_down
            "user",
            "chart_name",
            "ip_address",
            "project_id", #alias of project_id_app field
        )
        read_only_fields = ("created_on", "updated_on")

    def to_representation(self, instance):
        self.fields["user"] = UserSerializer(read_only=True)
        return super(DownloadVisualizationSerializer, self).to_representation(instance)


class MyPayloadSerializer(serializers.Serializer):
    def __init__(self, *args, viz=None, **kwargs):
        super().__init__(*args, **kwargs)
        global required_keys
        if viz == "circos":
            required_keys = {
                "filter": dict,
                "genes": list,
                "sampleKey": str,
                "type": str,
            }
        elif viz == "lollipop":
            required_keys = {
                "filter": dict,
                "genes": str,
                "table_type": str,
                "type": str,
            }
        elif viz == "cnv":
            required_keys = {"filter": dict, "genes": list, "type": str}
        elif viz == "boxplot":
            required_keys = {
                "filter": dict,
                "genes": list,
                "type": str,
                "table_type": str,
                "view": str,
            }
        elif viz == "scatter":
            required_keys = {"filter": dict, "genes": list, "type": str}
        elif viz == "heatmap":
            required_keys = {
                "filter": dict,
                "genes": list,
                "heat_type": str,
                "table_type": str,
                "type": str,
                "view": str,
            }
        elif viz == "survival":
            required_keys = {
                "filterType": str,
                "survival_type": str,
            }
        elif viz == "volcano":
            required_keys = {
                "filter": dict,
                "filterType": str,
                "genes": list,
                "type": str,
                "filterGroup": dict,
            }
        elif viz == "oncoprint":
            required_keys = {"filter": dict, "genes": list, "type": str}
        elif viz == "pca":
            required_keys = {"filter": dict, "genes": list, "table_type": str,"type": str}
        elif viz == "fusion":
            required_keys = {
                "filterType": str,
                "filterGroup": dict,
            }
        else:
            raise ValueError("Invalid viz")

    def validate_filter_data(self, filter_data, constant_filter_data):
        for key in filter_data:
            if key == "filterCondition":
                if filter_data[key] != "and" and filter_data[key] != "or":
                    raise serializers.ValidationError(f"Filter Condition Error ")
                continue
            if key not in constant_filter_data:
                raise serializers.ValidationError("Filter Key not Found")
            else:
                val_obj = constant_filter_data[key]
                if "type" in val_obj and val_obj["type"] == "number":
                    try:
                        value = float(filter_data[key])
                        assert value >= val_obj["min"] and value <= val_obj["max"]
                    except ValueError:
                        raise serializers.ValidationError(
                            f"{key} value should be between {val_obj[0]['type']['min']} and {val_obj[0]['type']['max']}"
                        )

                elif "type" in val_obj and val_obj["type"] == "checkbox":
                    try:
                        assert filter_data[key] == val_obj["value"]
                    except ValueError:
                        raise serializers.ValidationError("Incorrect Format of Data")
        return filter_data

    def validate(self, data):
        # Check for required keys
        request_data = self.context["request"].data.copy()
        constant_filter_data = self.context["constant_filter_data"].copy()
        missing_keys = set(required_keys.keys()).difference(set(request_data.keys()))
        if missing_keys:
            raise serializers.ValidationError(f"Missing keys: {missing_keys}")
        # Check that values are of the expected types
        for key, expected_type in required_keys.items():
            if key in request_data and not isinstance(request_data[key], expected_type):
                raise serializers.ValidationError(
                    f"Key {key} should be of type {expected_type.__name__}"
                )
        if "filter" in request_data and len(request_data["filter"]):
            request_data["filter"] = self.validate_filter_data(
                request_data["filter"], constant_filter_data
            )
        return request_data
