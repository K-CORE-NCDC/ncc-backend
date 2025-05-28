from rest_framework import serializers
from admin_app.models import *


class FaqSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityManagementFaq
        fields = "__all__"


class NoticeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityManagementNotice
        fields = "__all__"


class QASerializer(serializers.ModelSerializer):
    class Meta:
        model = CommunityManagementQnA
        fields = "__all__"
