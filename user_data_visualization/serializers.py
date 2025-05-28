from rest_framework import serializers
from app.models import *
from .models import UserDataProjects, UserDataExtension
from datetime import timedelta


class FileUplodSerializer(serializers.Serializer):
    dna_mutation = serializers.FileField(required=False)
    dna_methylation = serializers.FileField(required=False)
    rna_zscore = serializers.FileField(required=False)
    proteome = serializers.FileField(required=False)
    clinical_information = serializers.FileField(required=False)
    project_name = serializers.CharField()
    project_id = serializers.CharField()
    username = serializers.CharField()


class UserDataProjectsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDataProjects
        fields = "__all__"


class UserDataProjectsGetSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDataProjects
        fields = [
            "id",
            "name",
            "dna_mutation",
            "methylation",
            "rna",
            "proteome",
            "clinical_information",
            "available_steps",
            "cnv",
            "phospho",
            "fusion",
            "viz_type",
        ]

class UserDataExtensionSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserDataExtension
        fields = "__all__"
    expiration_date = serializers.SerializerMethodField()
    def get_expiration_date(self, obj):
        if obj.uploaded_date:
            if obj.extended_on:
                expiration_date = obj.uploaded_date + timedelta(days=28)
            else:
                expiration_date = obj.uploaded_date + timedelta(days=14)

            # Keep the same format for expiration_date
            return expiration_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        return None


class ProjectDataSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    project_id = serializers.IntegerField(source="id")
    project_name = serializers.CharField(source="name")
    clinical_information = serializers.SerializerMethodField(default=False)
    dna_mutation = serializers.SerializerMethodField(default=False)
    methylation = serializers.SerializerMethodField(default=False)
    rna = serializers.SerializerMethodField(default=False)
    proteome = serializers.SerializerMethodField(default=False)
    phospho = serializers.SerializerMethodField(default=False)
    cnv = serializers.SerializerMethodField(default=False)
    fusion = serializers.SerializerMethodField(default=False)
    uploaded_date = serializers.DateTimeField()
    expiration_date = serializers.SerializerMethodField()

    def get_clinical_information(self, obj):
        return obj.clinical_information is not None

    def get_dna_mutation(self, obj):
        return obj.dna_mutation is not None

    def get_methylation(self, obj):
        return obj.methylation is not None

    def get_rna(self, obj):
        return obj.rna is not None

    def get_proteome(self, obj):
        return obj.proteome is not None

    def get_phospho(self, obj):
        return obj.phospho is not None

    def get_cnv(self, obj):
        return obj.cnv is not None

    def get_fusion(self, obj):
        return obj.fusion is not None

    def get_expiration_date(self, obj):
        if obj.uploaded_date:
            expiration_date = obj.uploaded_date + timedelta(days=14)
            # Keep the same format for expiration_date
            return expiration_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        return None



class ClinicalInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClinicalInformation
        fields = "__all__"
