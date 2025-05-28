import csv
import os
import re
import six
import math
import uuid
import docker
import random
import base64
import pytz
import logging
import warnings
import numpy as np
import pandas as pd
from pandas import *
import sqlite3 as sql
from io import BytesIO
from collections import OrderedDict
from datetime import datetime, timezone
from subprocess import Popen, PIPE, STDOUT
from django.contrib.auth import authenticate, login, logout
from django.core.files.storage import default_storage
from django.views.decorators.csrf import csrf_protect, csrf_exempt, ensure_csrf_cookie
import zipfile
import time
from xhtml2pdf import pisa
from scipy import stats
import scipy.stats as stats
# This package was suggested my Haechang Bae and Miss Woo
from scipy.stats import kstest
from scipy.stats import bartlett
from scipy.stats import ttest_ind
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from statistics import mean
from sklearn.preprocessing import MinMaxScaler
from lifelines.statistics import multivariate_logrank_test
from pysurvival.models.non_parametric import KaplanMeierModel
from django import template
from django.conf import settings
import docker.errors as docker_errors
from django.core.mail import send_mail as sm
from django.db.models.functions import Concat
from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.core.exceptions import ObjectDoesNotExist
from django.db.utils import DatabaseError,IntegrityError
from django.db.models.aggregates import Count, Max, Min
from django.db.models import CharField, Count, F, Max, Min, Q, Value, When, Case
from django.http import HttpResponse,HttpResponseServerError,JsonResponse
from django.shortcuts import HttpResponse
from django.template.loader import get_template, render_to_string
from rest_framework import status
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.exceptions import APIException
from app.models import *
from app.serializers import *
from admin_app.models import *
from admin_app.serializers import NoticeSerializer
from user_data_visualization.models import *
from user_data_visualization.views import FilterJson, KeysAndValuesFilterJson
from .constants import (
    all_integer_cols,
    all_proteome_cols,
    dynamic_her2,
    dynamic_ki67,
    filterBoxes,
    filter_choices_column_names,
    onco_cusotom_queries,
    oncoqueries,
    dna_mutation_variant_classifications_list,
    variant_classifications_list,
    volcano_static,
    fusion_her2,
    advance_information_rows,
    fetch_user_project_object,
    filter_query_formater,
    orm_filter_query_formater,
    orm_advance_filter_query_formater,
    get_cox_object,
    int_converter,
    color,
    stack_data_generator,
    downloadPDF,
    int_converter_,
    format_number_roundup,
    add_line_in_logger_file,
)


User = get_user_model()

rnid_set = set()

logger = logging.getLogger(__name__)



@method_decorator(ensure_csrf_cookie, name="dispatch")
class GetCSRFToken(APIView):
    permission_classes = (permissions.AllowAny,)
    # --defined in settings.py default AllowAny, even if user is not logged in

    def get(self, request):
        return Response({"success": "CSRF Cookie Set"}, status=status.HTTP_200_OK)


@method_decorator(csrf_protect, name="dispatch")
class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({"msg": "User Logged out"})

@method_decorator(csrf_exempt, name="dispatch")
class NoticeApi(APIView):
    """Send Popup Data to frontend.

    Parameters
    ----------
    self, request : `Json request`
        @ params are empty .

    Returns
    -------
    returnValue : `json`
        only one object from CommunityManagementNotice which has active=True.
    """

    def get(self, request):
        try:

            notice = CommunityManagementNotice.objects.get(is_active=True)
            serializer = NoticeSerializer(notice)
            return Response({"data": serializer.data}, status=200)
        except CommunityManagementNotice.DoesNotExist:
            return Response({"data": {}}, status=204)
        except APIException as e:
            add_line_in_logger_file()
            logger.exception(e)
            return Response({"error": "An error occurred"}, status=500)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return Response({"error": "An error occurred"}, status=500)

@method_decorator(csrf_protect, name="dispatch")
class NewRegistration(APIView):
    """
    Handles new user registrations.

    This class extends Django's APIView to manage the process of registering new users.
    It includes methods for generating unique usernames, checking if a username is available,
    and handling the registration process.

    """
    def generate_username(self, last_id):
        prefix = "ncc-k00-"

        if last_id <= 9999:
            username = f"{prefix}{last_id:04d}"
        else:
            prefix = f"NCC-K{(last_id // 10000):02d}-"
            suffix = f"{(last_id % 10000):04d}"
            username = prefix + suffix
        return username

    def get(self, request):
        try:
            data = request.query_params
            input_value = data["value"]
            input_type = data["type"]
            if input_type == "username":
                if User.objects.filter(username=input_value).exists():
                    return Response(True, status=200)
            return Response(False, status=200)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return Response(status=500)

    def get_or_none(self, email):
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return None

    def post(self, request):
        try:
            data = request.data
            email = data.get("emailId")
            ct = datetime.now(pytz.timezone('Asia/Seoul'))

            user = self.get_or_none(email=email)
            if not user:
                try:
                    last_id = User.objects.latest("id").id if User.objects.exists() else 0
                    username = self.generate_username(last_id + 1)
                    unique_token = uuid.uuid4()
                    unique_pin = f"{random.randint(0, 9999):04}"
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return Response({"status": "SignupError"}, status=400)

                context = {
                    "username": username,
                    "set_password": f"{settings.FRONTEND_DOMAIN}set-password/{unique_token}/",
                    "unique_pin": unique_pin,
                    "frontend_domain": settings.FRONTEND_DOMAIN,
                    "datetime": ct.strftime("%Y-%m-%d %H:%M")
                }

                try:
                    user_mail = sm(
                        subject="K-CORE 회원가입 안내",
                        message="New User Registration",
                        html_message=render_to_string("UserAdminEmails/newregistrationuser.html", context),
                        from_email=settings.SENDER_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )

                    admin_mail = sm(
                        subject=f"[K-CORE] 회원가입 승인 요청 (분석접수번호: {username})",
                        message="New User Registration",
                        html_message=render_to_string("UserAdminEmails/newregistrationadmin.html", context),
                        from_email=settings.SENDER_EMAIL,
                        recipient_list=[settings.SENDER_EMAIL,
                                        # "ncdc@ncc.re.kr",
                                        # "nhwoo@3bigs.com"
                                        ],
                        fail_silently=False,
                    )
                    if user_mail > 0 and admin_mail > 0:
                        user, created = User.objects.get_or_create(username=username, email=email)
                        user.is_active = False
                        user.save()

                        profile_obj, created = Profile.objects.get_or_create(
                            user=user,
                            defaults={
                                "forget_password_token": unique_token,
                                "created_at": ct,
                                "unique_pin": unique_pin,
                            }
                        )

                        content = {"status": "Success"}
                        return Response(content, status=200)
                    else:
                        return Response({"status": "SignupEmailError"}, status=400)

                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return Response({"status": "SignupEmailError"}, status=400)
            else:
                return Response({"status": "SignupAlreadyExist"}, status=200)

        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return Response({"status": "SignupError"}, status=400)

@method_decorator(csrf_protect, name="dispatch")
class Login(APIView):
    """
    Handles user login functionality.

    This class extends Django's APIView to manage the process of user login.
    It includes methods for authenticating users and setting session cookies.
    """
    def post(self, request):
        try:
            data = self.request.data
            username = data.get("userId")
            password = data.get("password")

            user_obj = User.objects.get(username=username)

            if user_obj.is_active:
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    login(request, user)

                    response_data = {
                        "status": "Success",
                        "is_login": True,
                        "username": user.username,
                        "is_superuser": user.is_superuser,
                    }

                    response = Response(response_data, status=200)

                    request.session["username"] = user.username

                    if user.is_authenticated:
                        response.set_cookie(
                            "is_login",
                            value=True,
                            expires=request.session.get_expiry_date(),
                        )
                        response.set_cookie(
                            "username",
                            value=user.username,
                            expires=request.session.get_expiry_date(),
                        )
                        response.set_cookie(
                            "expiry",
                            value=request.session.get_expiry_date(),
                            expires=request.session.get_expiry_date(),
                        )

                    if user.is_superuser:
                        response.set_cookie(
                            "superuser",
                            value=user.is_superuser,
                            expires=request.session.get_expiry_date(),
                        )

                    return response
                else:
                    response_data = {"status": "LoginFailed", "is_login": False, "username": "", "is_superuser": False}
            else:
                response_data = {"status": "InActive", "is_login": False, "username": "", "is_superuser": False}
        except ObjectDoesNotExist:
            response_data = {"status": "UserDoesntExist", "is_login": False, "username": "", "is_superuser": False}
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            response_data = {"status": "An error occurred", "is_login": False, "username": "", "is_superuser": False}

        logger.exception(response_data)

        return Response(response_data, status=status.HTTP_200_OK)

@method_decorator(csrf_protect, name="dispatch")
class SankeyImageData(APIView):
    def post(self, request):
        try:
            data = request.data
            filename_ = data.get("filename") + data.get("unq")
            user_project_directory = f"{settings.BASE_DIR}/static"
            user_files_directory = os.path.join(user_project_directory, "Imagefiles")
            file_name = f"{filename_}.txt"

            if not os.path.exists(user_project_directory):
                os.makedirs(user_project_directory)
            if not os.path.exists(user_files_directory):
                os.makedirs(user_files_directory)

            db_path = os.path.join(user_files_directory, file_name)

            with open(db_path, "w") as f:
                f.write(str(data.get("imgdata")))

            return HttpResponse({})
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while saving the image data.")

@method_decorator(csrf_protect, name="dispatch")
class FindID(APIView):
    def post(self, request):
        try:
            data = request.data
            email = data.get("email_id")

            if email is not None:
                try:
                    user = User.objects.get(email=email)
                    userid = user.username
                    context = {"userid": userid, "frontend_url": settings.FRONTEND_DOMAIN}
                    id = user.user_id
                    status_is = "Success"
                    sm(
                        subject="K-CORE 분석접수번호 확인",
                        message=userid,
                        html_message=render_to_string("findid.html", context),
                        from_email=settings.SENDER_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )

                except User.DoesNotExist:
                    id = None
                    status_is = "EmailNotRegistered"

            else:
                status_is = "EmailNotRegistered"
                id = None

        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

        return Response({"ID": id, "status": status_is}, status=status.HTTP_200_OK)

@method_decorator(csrf_protect, name="dispatch")
class FindPassword(APIView):
    def post(self, request):
        try:
            data = request.data
            username = data.get("username")
            ct = datetime.now(pytz.timezone('Asia/Seoul'))
            status_is = ""
            token = str(uuid.uuid4())

            if username is not None:
                try:
                    user_obj = User.objects.get(username=username)

                    if user_obj.is_active:
                        username = user_obj.username
                        email = user_obj.email
                        profile_obj = None
                        context = {"username": username, "reset_password": f"{settings.FRONTEND_DOMAIN}resetpassword/{token}/"}
                        sm(
                            subject=f"K-CORE 비밀번호 재설정 안내",
                            message="reset password",
                            html_message=render_to_string("UserAdminEmails/userresetpassword.html", context),
                            from_email=settings.SENDER_EMAIL,
                            recipient_list=[email],
                            fail_silently=False,
                        )

                        try:
                            profile_obj = Profile.objects.get(user=user_obj)

                        except Profile.DoesNotExist:
                            profile_obj = None

                        if profile_obj is not None:
                            profile_obj.forget_password_token = token
                            profile_obj.created_at = ct
                            profile_obj.save()
                            status_is = "Success"
                        else:
                            profile_obj1 = Profile.objects.create(
                                user=user_obj, forget_password_token=token, created_at=ct
                            )
                            profile_obj1.save()
                            status_is = "Success"
                    else:
                        status_is = "InActive"
                except User.DoesNotExist:
                    status_is = "EmailNotRegistered"
            else:
                status_is = "Username Not Provided"
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        return Response({"status": status_is}, status=status.HTTP_200_OK)

@method_decorator(csrf_protect, name="dispatch")
class ChangePassword(APIView):
    def post(self, request):
        try:
            new_password = request.data.get("password")
            token = request.data.get("token")
            cp_type = request.data.get("cp_type")
            unique_pin = request.data.get("uniqueKey")

            try:
                profile_obj = Profile.objects.get(forget_password_token=token)
                user_obj = User.objects.get(pk=profile_obj.user_id)

                duration = datetime.now(pytz.timezone('Asia/Seoul')) - profile_obj.created_at
                duration_in_seconds = duration.total_seconds()

                if cp_type == "set_password":
                    if duration_in_seconds <= 3600:
                        user_obj.set_password(new_password)
                        user_obj.save()
                        return Response(
                            {"status": "Success"},
                            status=status.HTTP_200_OK,
                        )
                    else:
                        user_obj.delete()
                        profile_obj.delete()
                        return Response(
                            {"status": "PasswordSetLinkExpire"},
                            status=status.HTTP_200_OK
                        )
                elif cp_type == "reset_password":
                    if duration_in_seconds <= 3600:
                        if int_converter_(unique_pin) and int(unique_pin) == profile_obj.unique_pin:
                            user_obj.set_password(new_password)
                            user_obj.save()
                            return Response(
                                {"status": "Success"},
                                status=status.HTTP_200_OK,
                            )
                        else:
                            return Response(
                                {"status": "UniqueKeyError"},
                                status=status.HTTP_200_OK,
                            )
                    else:
                        return Response(
                            {"status": "PasswordResetLinkExpire"},
                            status=status.HTTP_200_OK
                        )
            except (Profile.DoesNotExist, User.DoesNotExist):
                return Response({"status": "UserDoesntExist"}, status=status.HTTP_200_OK)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class SankeyJson(APIView):
    def post(self, request, **args):
        try:
            Rdata = request.data if request.data else args["gmdata"]
            gene = Rdata["gene"] if request.data.get(
                "gene") else args["gmdata"]["gene"]
            mutations = (
                Rdata["mutation"]
                if "mutation" in request.data and len(request.data.get("mutation")) >= 0
                else args["gmdata"]["mutation"]
            )

            all_genes_final_result = {
                "nodes": [
                    {
                        "type": "Gene",
                        "id": 1,
                        "parent": None,
                        "number": "101",
                        "name": gene,
                    },
                ],
                "links": [],
            }

            final_result = []
            try:
                query_orm = (
                    GenevariantsankeyNew.objects.filter(
                        hugo_symbol=gene, variant_classification__in=mutations
                    )
                    .values(
                        "hugo_symbol",
                        "variant_classification",
                        "dbsnp_rs",
                        "diseasename",
                        "drugname",
                    )
                    .annotate(id=Value(1))
                ).distinct()
            except DatabaseError as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("A database error occurred while processing your request.")
            diseases = set()
            rows = query_orm

            # New Logic
            dbsnp_rs_set = set()
            drugname_set = set()

            for e in query_orm:
                if len(dbsnp_rs_set) >= 20 or len(diseases) >= 15:
                    break

                if "dbsnp_rs" in e and len(dbsnp_rs_set) < 20:
                    dbsnp_rs = e["dbsnp_rs"]
                    dbsnp_rs_set.add(dbsnp_rs)

                if "drugname" in e and len(drugname_set) < 20:
                    drugname = e["drugname"]
                    drugname_set.add(drugname)

                if "diseasename" in e and len(diseases) <= 15:
                    diseases.add(e["diseasename"])

                final_result.append(
                    {
                        "hugo_symbol": e["hugo_symbol"],
                        "variant_classification": e["variant_classification"],
                        "dbsnp_rs": e["dbsnp_rs"],
                        "diseasename": e["diseasename"],
                        "drugname": e["drugname"],
                    }
                )

            tmp = {}
            i = 2
            link_list = []

            if rows is not None:
                for e in rows:
                    v = i
                    rs = v + 2
                    dis = rs + 3
                    drug = dis + 4
                    link_list.extend([v, rs, dis, drug])
                    if (
                        "variant_classification" in e
                        and e["variant_classification"] is not None
                    ):
                        if e["variant_classification"] not in tmp:
                            number = v * 1
                            tmp[e["variant_classification"]] = v
                            all_genes_final_result["nodes"].append(
                                {
                                    "type": "Variant",
                                    "id": v,
                                    "parent": None,
                                    "number": str(number + 1),
                                    "name": e["variant_classification"],
                                }
                            )
                    if "dbsnp_rs" in e and e["dbsnp_rs"] is not None:
                        if e["dbsnp_rs"] not in tmp:
                            number = rs * 2
                            tmp[e["dbsnp_rs"]] = rs
                            all_genes_final_result["nodes"].append(
                                {
                                    "type": "Rsid",
                                    "id": rs,
                                    "parent": None,
                                    "number": str(number + 1),
                                    "name": e["dbsnp_rs"],
                                }
                            )
                    if "diseasename" in e and e["diseasename"] is not None:
                        if e["diseasename"] not in tmp:
                            number = dis * 3
                            tmp[e["diseasename"]] = dis
                            all_genes_final_result["nodes"].append(
                                {
                                    "type": "Disease",
                                    "id": dis,
                                    "parent": None,
                                    "number": str(number + 1),
                                    "name": e["diseasename"],
                                }
                            )
                    if "drugname" in e and e["drugname"] is not None:
                        if e["drugname"] not in tmp:
                            number = drug * 4
                            tmp[e["drugname"]] = drug
                            all_genes_final_result["nodes"].append(
                                {
                                    "type": "Drug",
                                    "id": drug,
                                    "parent": None,
                                    "number": str(number + 1),
                                    "name": e["drugname"],
                                }
                            )

                    if (gene is not None) and (e["variant_classification"] is not None):
                        tmp_key = "1-" + str(tmp[e["variant_classification"]])
                        if tmp_key not in tmp:
                            tmp[tmp_key] = ""
                            all_genes_final_result["links"].append(
                                {
                                    "source": 1,
                                    "target": tmp[e["variant_classification"]],
                                    "value": random.randint(1, 10),
                                }
                            )

                    if (e["variant_classification"] is not None) and (
                        e["dbsnp_rs"] is not None
                    ):

                        tmp_key = (
                            str(tmp[e["variant_classification"]])
                            + "-"
                            + str(tmp[e["dbsnp_rs"]])
                        )
                        if tmp_key not in tmp:
                            tmp[tmp_key] = ""
                            all_genes_final_result["links"].append(
                                {
                                    "source": tmp[e["variant_classification"]],
                                    "target": tmp[e["dbsnp_rs"]],
                                    "value": random.randint(1, 10),
                                }
                            )
                    if (e["dbsnp_rs"] is not None) and (e["diseasename"] is not None):
                        tmp_key = str(tmp[e["dbsnp_rs"]]) + \
                            "-" + str(tmp[e["diseasename"]])
                        if tmp_key not in tmp:
                            tmp[tmp_key] = ""
                            all_genes_final_result["links"].append(
                                {
                                    "source": tmp[e["dbsnp_rs"]],
                                    "target": tmp[e["diseasename"]],
                                    "value": random.randint(1, 10),
                                }
                            )

                    if (e["diseasename"] is not None) and (
                        "drugname" in e and e["drugname"] is not None
                    ):
                        tmp_key = str(tmp[e["diseasename"]]) + \
                            "-" + str(tmp[e["drugname"]])
                        if tmp_key not in tmp:
                            tmp[tmp_key] = ""
                            all_genes_final_result["links"].append(
                                {
                                    "source": tmp[e["diseasename"]],
                                    "target": tmp[e["drugname"]],
                                    "value": random.randint(1, 10),
                                }
                            )
                    i = drug + 1

            link_list = list(set(link_list))

            orders = ["Gene", "Variant", "Rsid", "Disease", "Drug"]
            final_node = []
            for order in orders:
                for e in all_genes_final_result["nodes"]:
                    if order == e["type"]:
                        final_node.append(e)
            all_genes_final_result["nodes"] = final_node

            if request.data:
                return Response(final_result, status=status.HTTP_200_OK)
            else:
                return Response(all_genes_final_result, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class Report(APIView):
    def post(self, request):
        try:
            rnid = request.data.get("rnid")
            project_id = request.data.get("project_id")
            gene_list = request.data.get("genes")
            tmp_variants = {}
            dna_mutation_tmp_variants = {}
            rna_query = {}
            response_data = {
                "Basic_Information": {
                    "sample": rnid,
                    "sex_cd": "",
                    "diag_age": [],
                    "bmi_vl": [],
                    "drnk_yn": "",
                    "smok_yn": "",
                    "diabetes_yn": "",
                    "hyp_yn": "",
                },
                "Genomic_Information": {
                    "Dna_Mutation": {},
                    "Rna_Expression": {},
                    "Proteome_Expression": {},
                },
            }
            result = {}
            if rnid is None:
                return Response({"status": "BAD Request"}, status=status.HTTP_403_FORBIDDEN)
            else:
                if project_id is None:
                    clinical_information_ob = (
                        ClinicalInformation.objects.filter(pt_sbst_no=rnid)
                        .order_by("rnid")
                        .reverse()
                    )
                    if clinical_information_ob is not None:
                        for singleobj in clinical_information_ob:
                            if singleobj.sex_cd is not None:
                                response_data["Basic_Information"][
                                    "sex_cd"
                                ] = singleobj.sex_cd

                            if singleobj.diag_age is not None:
                                response_data["Basic_Information"]["diag_age"].append(
                                    singleobj.diag_age
                                )

                            if singleobj.bmi_vl is not None:
                                response_data["Basic_Information"]["bmi_vl"].append(
                                    singleobj.bmi_vl
                                )

                            if singleobj.drnk_yn is not None:
                                if singleobj.drnk_yn == True:
                                    response_data["Basic_Information"]["drnk_yn"] = "Yes"
                                elif singleobj.drnk_yn == False:
                                    response_data["Basic_Information"]["drnk_yn"] = "No"
                                else:
                                    response_data["Basic_Information"]["drnk_yn"] = "NA"

                            if singleobj.diabetes_yn is not None:
                                if singleobj.diabetes_yn == True:
                                    response_data["Basic_Information"]["diabetes_yn"] = "Yes"
                                elif singleobj.diabetes_yn == False:
                                    response_data["Basic_Information"]["diabetes_yn"] = "No"
                                else:
                                    response_data["Basic_Information"]["diabetes_yn"] = "NA"

                            if singleobj.hyp_yn is not None:
                                if singleobj.hyp_yn == True:
                                    response_data["Basic_Information"]["hyp_yn"] = "Yes"
                                elif singleobj.hyp_yn == False:
                                    response_data["Basic_Information"]["hyp_yn"] = "No"
                                else:
                                    response_data["Basic_Information"]["hyp_yn"] = "NA"


                            if singleobj.smok_yn is not None:
                                if singleobj.smok_yn == True:
                                    response_data["Basic_Information"]["smok_yn"] = "Yes"
                                elif singleobj.smok_yn == False:
                                    response_data["Basic_Information"]["smok_yn"] = "No"
                                else:
                                    response_data["Basic_Information"]["smok_yn"] = "NA"

                            break
                        response_data["Basic_Information"]["diag_age"] = map(
                            str,
                            list(
                                dict.fromkeys(
                                    response_data["Basic_Information"]["diag_age"]
                                )
                            ),
                        )

                        response_data["Basic_Information"]["bmi_vl"] = map(
                            str,
                            list(
                                dict.fromkeys(
                                    response_data["Basic_Information"]["bmi_vl"])
                            ),
                        )
                        diag_age = ", ".join(
                            (response_data["Basic_Information"]["diag_age"])
                        )
                        bmi_val = ", ".join(
                            (response_data["Basic_Information"]["bmi_vl"]))
                        basic_information = []
                        basic_information.append(
                            {
                                "Sample": rnid,
                                "Sex": response_data["Basic_Information"]["sex_cd"],
                                "Age Of Diagnosis (1st Day Of Diagnosis)": diag_age,
                                "BMI (1st Day Of Diagnosis)": bmi_val,
                                "Alcohol Consumtion": response_data["Basic_Information"][
                                    "drnk_yn"
                                ],
                                "Smoking Status": response_data["Basic_Information"][
                                    "smok_yn"
                                ],
                                "Diabetes History": response_data["Basic_Information"][
                                    "diabetes_yn"
                                ],
                                "Hypertension History": response_data["Basic_Information"][
                                    "hyp_yn"
                                ],
                            }
                        )
                        result["basic_information"] = basic_information

                if project_id:
                    result["basic_information"] = []
                    query = (
                        "select distinct 1 as id,* from clinical_information where pt_sbst_no='"
                        + rnid
                        + "'"
                    )
                    for e in ClinicalInformation.objects.using(settings.DB).raw(query):
                        row = e.__dict__
                        dynamic_data = {}
                        for key, value in row.items():
                            if key not in ["_state", "id", "rnid_id"]:
                                dynamic_data[key] = (
                                    str(value) if str(value) != None else "NA"
                                )
                        result["basic_information"].append(dynamic_data)

                if project_id is not None:
                    available_steps = fetch_user_project_object(project_id)
                    available_steps_sankey = available_steps.get("sankey")
                rna_query = []
                proteome_query = []
                dna_mutation_query = []

                if (project_id and "rna" in available_steps_sankey) or project_id is None:
                    rna_query = (
                        Rna.objects.using(settings.DB)
                        .filter(pt_sbst_no=rnid, gene_name__in=gene_list)
                        .values("gene_name", "z_score")
                        .annotate(id=F("pk"))
                    )

                if (
                    project_id and "proteome" in available_steps_sankey
                ) or project_id is None:
                    proteome_query = (
                        Proteome.objects.using(settings.DB)
                        .extra(
                            select={
                                "id": "1",
                                "gene_name": "gene_name",
                                "z_score": "z_score",
                            }
                        )
                        .filter(pt_sbst_no=rnid, gene_name__in=gene_list)
                        .values("gene_name", "z_score")
                    )

                if (
                    project_id and "dna_mutation" in available_steps_sankey
                ) or project_id is None:
                    dna_mutation_query = (
                        DnaMutation.objects.using(settings.DB)
                        .filter(
                            tumor_sample_barcode=rnid,
                            hugo_symbol__in=gene_list,
                            variant_classification__in=dna_mutation_variant_classifications_list,
                        )
                        .values(
                            "id",
                            "hugo_symbol",
                            "variant_classification",
                            "tumor_sample_barcode",
                        )
                    )

                sankey_gene_variant_classification_query = (
                    GenevariantsankeyNew.objects.filter(
                        hugo_symbol__in=gene_list,
                        variant_classification__in=variant_classifications_list,
                    )
                    .values(
                        "id",
                        "hugo_symbol",
                        "variant_classification",
                    )
                    .distinct()
                )
                if rna_query is not None:
                    for e in rna_query:
                        response_data["Genomic_Information"]["Rna_Expression"][
                            e["gene_name"]
                        ] = ""
                        if e["z_score"] is not None:
                            if e["z_score"] <= -1:
                                response_data["Genomic_Information"]["Rna_Expression"][
                                    e["gene_name"]
                                ] = "LOW"
                            elif e["z_score"] >= 1:
                                response_data["Genomic_Information"]["Rna_Expression"][
                                    e["gene_name"]
                                ] = "HIGH"

                if proteome_query is not None:
                    for e in proteome_query:
                        response_data["Genomic_Information"]["Proteome_Expression"][
                            e["gene_name"]
                        ] = ""
                        if e["z_score"] is not None:
                            if e["z_score"] <= -1:
                                response_data["Genomic_Information"]["Proteome_Expression"][
                                    e["gene_name"]
                                ] = "LOW"
                            elif e["z_score"] >= 1:
                                response_data["Genomic_Information"]["Proteome_Expression"][
                                    e["gene_name"]
                                ] = "HIGH"

                if dna_mutation_query is not None:
                    for e in dna_mutation_query:
                        response_data["Genomic_Information"]["Dna_Mutation"][
                            e["hugo_symbol"]
                        ] = "YES"

                    for gene in gene_list:
                        if gene not in response_data["Genomic_Information"]["Dna_Mutation"]:
                            response_data["Genomic_Information"]["Dna_Mutation"][
                                gene
                            ] = "NO"

                if dna_mutation_query is not None:
                    for e in dna_mutation_query:
                        if e["hugo_symbol"] in dna_mutation_tmp_variants:
                            if (
                                e["variant_classification"]
                                not in dna_mutation_tmp_variants[e["hugo_symbol"]]
                            ):
                                dna_mutation_tmp_variants[e["hugo_symbol"]].append(
                                    e["variant_classification"]
                                )
                        else:
                            dna_mutation_tmp_variants[e["hugo_symbol"]] = [
                                    e["variant_classification"]]

                if sankey_gene_variant_classification_query is not None:
                    for e in sankey_gene_variant_classification_query:
                        if e["hugo_symbol"] in tmp_variants:
                            if (
                                e["variant_classification"]
                                not in tmp_variants[e["hugo_symbol"]]
                            ):
                                tmp_variants[e["hugo_symbol"]].append(
                                    e["variant_classification"]
                                )
                        else:
                            tmp_variants[e["hugo_symbol"]] = [
                                e["variant_classification"]]

                genomic_summary = []
                for each in gene_list:
                    obj = {}
                    obj["gene"] = each

                    if (
                        project_id and "dna_mutation" in available_steps_sankey
                    ) or project_id is None:
                        dna = ""
                        if each in response_data["Genomic_Information"]["Dna_Mutation"]:
                            dna = response_data["Genomic_Information"]["Dna_Mutation"][each]
                        obj["dna"] = dna

                    if (
                        project_id and "rna" in available_steps_sankey
                    ) or project_id is None:
                        rna = ""
                        if each in response_data["Genomic_Information"]["Rna_Expression"]:
                            rna = response_data["Genomic_Information"]["Rna_Expression"][
                                each
                            ]
                        obj["rna"] = rna

                    if (
                        project_id and "proteome" in available_steps_sankey
                    ) or project_id is None:
                        proteome = ""
                        if (
                            each
                            in response_data["Genomic_Information"]["Proteome_Expression"]
                        ):
                            proteome = response_data["Genomic_Information"][
                                "Proteome_Expression"
                            ][each]
                        obj["proteome"] = proteome

                    genomic_summary.append(obj)

                response_sanky_data = {}
                result["variant_info"] = tmp_variants
                result["dna_mutation_variant_info"] = dna_mutation_tmp_variants
                result["genomic_summary"] = genomic_summary
                result["response_sanky_data"] = response_sanky_data
                return Response(result, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class DataSummaryList(APIView):

    """Send Data Summary List to Frontend.
    Parameters
    ----------
    self, request : `No Payload`
        Get Request with no payload - @ No parameters

    Returns
    -------
    returnValue : `json`
        Sending distinct values of Basic/Diagnostic Information,Patient Health Information,Clinical Information,Follow-up Observation
        from Clinincal information.
    """

    def get(self, request):
        try:
            sex_res = ClinicalInformation.objects.raw(
                "SELECT 1 as id, sex_cd as name, count(distinct rnid.rn_key) as cnt from rnid left join pe_rlps on rnid.rn_key=pe_rlps.pt_sbst_no group by sex_cd"
            )
            sex_serializer_data = commonSerializer(sex_res, many=True)
            sex_data = sex_serializer_data.data
            sex_data.append({"name": "M", "cnt": ""})

            diag_res = ClinicalInformation.objects.raw(
                "SELECT 1 as id, diag_age as name, count(distinct rnid.rn_key) as cnt from rnid left join pe_rlps on rnid.rn_key=pe_rlps.pt_sbst_no group by diag_age "
            )
            diag_age_list = [
                {"name": "25~40", "cnt": 0},
                {"name": "41~55", "cnt": 0},
                {"name": "56~70", "cnt": 0},
                {"name": "71~90", "cnt": 0},
            ]
            for each_diag_age in diag_res:
                age = int(each_diag_age.name)
                if age <= 25:
                    diag_age_list[0]["cnt"] += int(each_diag_age.cnt)
                elif age > 25 and age <= 40:
                    diag_age_list[1]["cnt"] += int(each_diag_age.cnt)
                elif age > 40 and age <= 55:
                    diag_age_list[2]["cnt"] += int(each_diag_age.cnt)
                elif age > 55 and age <= 70:
                    diag_age_list[2]["cnt"] += int(each_diag_age.cnt)
                elif age > 70 and age <= 90:
                    diag_age_list[3]["cnt"] += int(each_diag_age.cnt)
                else:
                    diag_age_list[4]["cnt"] += int(each_diag_age.cnt)
            dia_age_serializer_data = commonSerializer(diag_age_list, many=True)

            q = "select distinct 1 as id,r.rn_key,c.bmi_vl from rnid r left join clinical_information c on c.rnid=r.id order by c.bmi_vl asc"
            bmi_res = ClinicalInformation.objects.raw(q)
            t = {"N/A": set()}
            bmi_rnid_set = set()
            for each in bmi_res:
                rnid = each.rn_key
                if rnid in bmi_rnid_set:
                    continue
                else:
                    bmi_rnid_set.add(rnid)
                if each.bmi_vl is not None:
                    bmi = each.bmi_vl
                    tmp = each.bmi_vl - bmi
                    tmp = "%.1f" % tmp
                    tmp = float(tmp)

                    if t.get(bmi) is None:
                        t[bmi] = {rnid}
                    else:
                        t[bmi].add(rnid)
                else:
                    t["N/A"].add(each.rn_key)

            z = [{"name": k, "cnt": len(v)} for k, v in t.items()]
            bmi_serializer_data = commonSerializer(z, many=True)

            bila_res = ClinicalInformation.objects.raw(
                "SELECT 1 as id, bila_cncr_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join pe_rlps on rnid.rn_key=pe_rlps.pt_sbst_no group by bila_cncr_yn order by name desc"
            )
            bila_serializer_data = commonSerializer(bila_res, many=True)

            smoking_res = ClinicalInformation.objects.raw(
                "SELECT 1 as id, mr_hlth.smok_yn,mr_hlth.smok_curr_yn,rnid.rn_key from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no"
            )
            smok = {"current smoking": 0, "past smoking": 0,
                    "non smoking": 0, "N/A": 0}
            for e in smoking_res:
                if e.smok_yn == "Y":
                    if not e.smok_curr_yn == "N":
                        smok["past smoking"] += 1
                elif e.smok_yn == "N":
                    smok["non smoking"] += 1
                else:
                    smok["N/A"] += 1

                if e.smok_curr_yn == "Y":
                    smok["current smoking"] += 1

            smok_d = [{"name": k, "cnt": v} for k, v in smok.items()]

            drnk_res = ClinicalInformation.objects.raw(
                "SELECT 1 as id, drnk_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by  drnk_yn order by name desc"
            )
            drnk_data = commonSerializer(drnk_res, many=True)
            hyp_res = ClinicalInformation.objects.raw(
                "SELECT 1 as id, hyp_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by hyp_yn order by name desc"
            )
            hyp_data = commonSerializer(hyp_res, many=True)
            diabetes_res = ClinicalInformation.objects.raw(
                "SELECT 1 as id, diabetes_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by diabetes_yn order by name desc"
            )
            diabetes_data = commonSerializer(diabetes_res, many=True)

            # fmhs_res = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, fmhs_brst_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by  fmhs_brst_yn order by name desc"
            # )
            # fmhs_data = commonSerializer(fmhs_res, many=True)

            # mena_res = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, mena_age as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by  mena_age order by name asc"
            # )
            # mena_data = commonSerializer(mena_res, many=True)

            # menopause_res = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, meno_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by  meno_yn order by name desc"
            # )
            # meno_data = commonSerializer(menopause_res, many=True)

            # delv_res = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, delv_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by  delv_yn order by name desc"
            # )
            # delv_data = commonSerializer(delv_res, many=True)

            # feed_res = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, feed_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by  feed_yn order by name desc"
            # )
            # feed_data = commonSerializer(feed_res, many=True)

            # breast_feed_res = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id,feed_yn, feed_drtn_year,feed_drtn_mnth,rnid.rn_key from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no where mr_hlth.feed_yn='Y'"
            # )

            # t = {13: 0}
            # na = {"N/A": 0}
            # for e in breast_feed_res:
            #     if e.feed_drtn_mnth is not None or e.feed_drtn_year is not None:
            #         feed_mnth = 0
            #         if e.feed_drtn_mnth is not None:
            #             feed_mnth = int(e.feed_drtn_mnth)
            #         feed_year = 0
            #         if e.feed_drtn_year is not None:
            #             feed_year = int(e.feed_drtn_year)
            #         if feed_mnth <= 12:
            #             if feed_year < 1:
            #                 if feed_mnth in t:
            #                     t[feed_mnth] = t[feed_mnth] + 1
            #                 else:
            #                     t[feed_mnth] = 1
            #         if feed_year > 0:
            #             t[13] += 1
            #     else:
            #         na["N/A"] += 1

            # t = OrderedDict(sorted(t.items(), key=lambda t: t[0]))
            # final_breast_feed = [{"name": str(k), "cnt": v} for k, v in t.items()]
            # final_breast_feed.append({"name": "N/A", "cnt": na["N/A"]})

            # final_breast_feed = commonSerializer(final_breast_feed, many=True)

            # oc_yn = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, oc_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by oc_yn order by name desc"
            # )
            # oc_yn_serializer = commonSerializer(oc_yn, many=True)

            # hrt_yn = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, hrt_yn as name, count(distinct rnid.rn_key) as cnt from rnid left join mr_hlth on rnid.rn_key=mr_hlth.pt_sbst_no group by hrt_yn order by name desc"
            # )
            # hrt_yn_serializer = commonSerializer(hrt_yn, many=True)
            #
            # t_stage_keys = {"Tis": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0, "N/A": 0}
            t_stage_keys = {"T1": 0, "T2": 0, "T3": 0, "T4": 0, "N/A": 0}
            t_stage = ClinicalInformation.objects.raw(
                "SELECT distinct 1 as id, t_category as name,count(distinct rnid) as cnt from clinical_information group by t_category order by t_category asc"
            )
            for e in t_stage:
                if e.name is not None:
                    t_stage_keys[e.name] = e.cnt
            t_stage = [{"name": str(k), "cnt": v} for k, v in t_stage_keys.items()]
            t_stage_serializer = commonSerializer(t_stage, many=True)

            # n_cat_keys = {"NX": 0, "N0": 0, "N1": 0, "N2": 0, "N3": 0, "N/A": 0}
            n_cat_keys = {"N0": 0, "N1": 0, "N2": 0, "N3": 0, "N/A": 0}
            n_category = ClinicalInformation.objects.raw(
                "SELECT distinct 1 as id, n_category as name,count(distinct rnid) as cnt from clinical_information group by n_category order by n_category asc"
            )
            for e in n_category:
                if e.name is not None:
                    n_cat_keys[e.name] = e.cnt
            n_category = [{"name": str(k), "cnt": v}
                        for k, v in n_cat_keys.items()]
            n_category_serializer = commonSerializer(n_category, many=True)

            stage_keys = {"Stage_I": 0, "Stage_II": 0, "Stage_III": 0, "Stage_IV": 0, "N/A": 0}
            stage = ClinicalInformation.objects.raw(
                "SELECT distinct 1 as id, stage as name,count(distinct rnid) as cnt from clinical_information group by stage order by stage asc"
            )
            for e in stage:
                if e.name is not None:
                    stage_keys[e.name] = e.cnt
            stage = [{"name": str(k), "cnt": v}
                        for k, v in stage_keys.items()]
            stage_serializer = commonSerializer(stage, many=True)

            # q = "select er_score,count(pt_sbst_no) as id  from clinical_information   group by er_score"
            # er_test_result_object = ClinicalInformation.objects.raw(q)
            # er_test_result_dict = {}
            # for er_val in er_test_result_object:
            #     name = "N/A"
            #     if er_val.er_score == 1:
            #         name = "Positive"
            #     elif er_val.er_score == 2:
            #         name = "Negative"
            #     er_test_result_dict[name] = er_val.id
            # er_test_result = [{"name": k, "cnt": v}
            #                 for k, v in er_test_result_dict.items()]
            # er_test_result_serializer = commonSerializer(er_test_result, many=True)

            # pr_test_result_object = ClinicalInformation.objects.raw(
            #     "select pr_score,count(pt_sbst_no) as id  from clinical_information   group by pr_score"
            # )
            # pr_test_result_dict = {}
            # for pr_val in pr_test_result_object:
            #     name = "N/A"
            #     if pr_val.pr_score == 1:
            #         name = "Positive"
            #     elif pr_val.pr_score == 2:
            #         name = "Negative"
            #     pr_test_result_dict[name] = pr_val.id

            # pr_test_result = [{"name": k, "cnt": v}
            #                 for k, v in pr_test_result_dict.items()]
            # pr_test_result_serializer = commonSerializer(pr_test_result, many=True)

            # her2_score_result = ClinicalInformation.objects.raw(
            #     "select her2_score,count(pt_sbst_no) as id  from clinical_information group by her2_score order by her2_score asc"
            # )
            # her2_rnid_dict = {}
            # for m in her2_score_result:
            #     if m.her2_score:
            #         her2_rnid_dict[m.her2_score] = m.id
            #     else:
            #         her2_rnid_dict["N/A"] = m.id

            # her = [
            #     {"name": "0~1", "cnt": v} if k == "0~1+" else {"name": k, "cnt": v}
            #     for k, v in her2_rnid_dict.items()
            # ]
            # her2_score_result_serializer = commonSerializer(her, many=True)

            # ki67_score_result = ClinicalInformation.objects.raw(
            #     "SELECT 1 as id, ki67_score as name, count(distinct rnid) as cnt from clinical_information group by ki67_score order by name"
            # )
            # ki67_score_key = {}
            # ki67_score_list = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
            # for each in ki67_score_result:
            #     if each.name is not None:
            #         name = int(each.name)
            #         key = 0
            #         for e in ki67_score_list:
            #             if name < e:
            #                 key = e
            #                 break

            #         if key in ki67_score_key:
            #             ki67_score_key[key] = ki67_score_key[key] + each.cnt
            #         else:
            #             ki67_score_key[key] = each.cnt

            # final_ki67_score_result = []
            # for k, v in ki67_score_key.items():
            #     final_ki67_score_result.append({"name": k, "cnt": v})

            # ki67_score_result_serializer = commonSerializer(
            #     final_ki67_score_result, many=True
            # )

            recur_yn = ClinicalInformation.objects.raw(
                "SELECT 1 as id, rlps_yn as name, count(pt_sbst_no) as cnt from clinical_information group by name order by name desc"
            )
            cancer_recurrence_serializer = commonSerializer(recur_yn, many=True)

            recur_cnfr_drtn = ClinicalInformation.objects.raw(
                "SELECT 1 as id, recur_cnfr_drtn,rnid.rn_key from rnid left join pe_rlps on rnid.rn_key=pe_rlps.pt_sbst_no order by recur_cnfr_drtn asc"
            )
            t = {}
            for e in recur_cnfr_drtn:
                if e.recur_cnfr_drtn is not None:
                    drtn = math.ceil(e.recur_cnfr_drtn / 12)
                    if drtn in t:
                        t[drtn] += 1
                    else:
                        t[drtn] = 1
            time_relapse_serializer = [
                {"name": str(k), "cnt": v} for k, v in t.items()]

            final_list = []
            for i in range(len(sex_data)):
                if sex_data[i]["name"] == "M":
                    sex_data[i]["name"] = "Male"
                elif sex_data[i]["name"] == "F":
                    sex_data[i]["name"] = "Female"

            # for i in range(len(bila_serializer_data.data)):
            #     if bila_serializer_data.data[i]["name"] == "Y":
            #         bila_serializer_data.data[i]["name"] = "Yes"
            #         final_list.append(bila_serializer_data.data[i])
            #     elif bila_serializer_data.data[i]["name"] == "N":
            #         bila_serializer_data.data[i]["name"] = "No"
            #         final_list.append(bila_serializer_data.data[i])
            res = {
                "Basic/Diagnostic Information": {
                    "Sex": sex_data,
                    "Age Of Diagnosis": dia_age_serializer_data.data,
                    "Body Mass Index": bmi_serializer_data.data,
                    "Diagnosis Of Bilateral Breast Cancer": final_list,
                },
                "Patient Health Information": {
                    "Smoking Status": smok_d,
                    "Alcohol Consumption": drnk_data.data,
                    "Hypertension History": hyp_data.data,
                    "Diabetes History": diabetes_data.data,
                    # "Menopause": meno_data.data,
                    # "Childbirth": delv_data.data,
                    # "Experience of Breastfeeding": feed_data.data,
                    # "Duration of Breastfeeding": final_breast_feed.data,
                    # "Intake of Oral Contraceptive Pill": oc_yn_serializer.data,
                    # "Hormone Replacement Therapy": hrt_yn_serializer.data,
                },
                "Clinical Information": {
                    "T Category": t_stage_serializer.data,
                    "N Category": n_category_serializer.data,
                    "Stage": stage_serializer.data,
                    # "PR Test Results": pr_test_result_serializer.data,
                    # "HER2 Score": her2_score_result_serializer.data,
                    # "Ki-67 Index": ki67_score_result_serializer.data,
                },
                "Follow-up Observation": {
                    "Cancer Recurrence": cancer_recurrence_serializer.data,
                    "Time until relapse is confirmed": time_relapse_serializer,
                },
            }
            return Response(res, status=200)
        except ObjectDoesNotExist as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

class GeneInfo(APIView):
    def post(self, request):
        try:
            advanced_filter = ""
            selected_genes = []
            if "filter" in request.data and len(request.data.get("filter")):
                advanced_filter = request.data.get("filter")
                advanced_filter = filter_query_formater(advanced_filter)
            if "genes" in request.data:
                selected_genes = request.data.get("genes")
            mutations = [
                "In_Frame_Ins",
                "Frame_Shift_Del",
                "Frame_Shift_Ins",
                "Missense_Mutation",
                "Nonsense_Mutation",
                "Splice_Site",
                "In_Frame_Del",
                "Germline",
            ]

            project_id = None
            if request.data.get("project_id"):
                project_id = request.data.get("project_id")

            dna_mutation_query = "select distinct 1 as id, dna.variant_classification as name,count(dna.rnid) as cnt from dna_mutation as dna"
            if advanced_filter != "":
                dna_mutation_query += " inner join clinical_information on dna.tumor_sample_barcode = clinical_information.pt_sbst_no"
            dna_mutation_query += " where dna.variant_classification in " + str(
                tuple(mutations)
            )
            if advanced_filter != "":
                dna_mutation_query += " and " + advanced_filter
            dna_mutation_query += " group by name order by cnt desc limit 10"
            if project_id is not None:
                dna_mutation_res = DnaMutation.objects.using(settings.DB).raw(
                    dna_mutation_query
                )
                variant_rest_data = commonSerializer(dna_mutation_res, many=True)

            else:
                dna_mutation_res = DnaMutation.objects.raw(dna_mutation_query)
                variant_rest_data = commonSerializer(dna_mutation_res, many=True)

            variant_type_query = "SELECT 1 as id,dna.variant_type as name,count(dna.rnid) as cnt FROM dna_mutation as dna"
            if advanced_filter != "":
                variant_type_query += " inner join clinical_information on dna.tumor_sample_barcode = clinical_information.pt_sbst_no"
            variant_type_query += " where dna.variant_classification in " + str(
                tuple(mutations)
            )
            if advanced_filter != "":
                variant_type_query += " and " + "(" + advanced_filter + ")"
            variant_type_query += " group by name order by cnt desc"
            if project_id is not None:
                variant_type_data = DnaMutation.objects.using(settings.DB).raw(
                    variant_type_query
                )
                variant_type_data = dnamutationSerializer(
                    variant_type_data, many=True)
            else:
                variant_type_data = DnaMutation.objects.raw(variant_type_query)
                variant_type_data = dnamutationSerializer(
                    variant_type_data, many=True)

            """
                snv_query = "SELECT 1 as id,name,sum(cnt) as cnt FROM snv_class"
                if advanced_filter != '':
                    snv_query += " inner join clinical_information on snv_class.tumor_sample_barcode = clinical_information.pt_sbst_no"
                    snv_query += " where "+advanced_filter
                snv_query += " group by name order by cnt desc limit 10"
                if project_id is not None:
                    snv_data = DnaMutation.objects.using(
                        settings.DB).raw(snv_query)
                    snv_data = dnamutationSerializer(snv_data, many=True)

                else:
                    snv_data = DnaMutation.objects.raw(snv_query)
                    snv_data = dnamutationSerializer(snv_data, many=True)

                """
            top_genes_query = "select 1 as id,dna.hugo_symbol as label,count(*) as cnt from dna_mutation as dna"
            if advanced_filter != "":
                top_genes_query += " inner join clinical_information on dna.tumor_sample_barcode = clinical_information.pt_sbst_no"

            top_genes_query += " where dna.variant_classification in " + \
                str(tuple(mutations))

            if len(selected_genes) == 1:
                top_genes_query += f" AND dna.hugo_symbol = '{selected_genes[0]}'"
            elif len(selected_genes) > 1:
                top_genes_query += f" AND dna.hugo_symbol IN {str(tuple(selected_genes))}"

            if advanced_filter != "":
                top_genes_query += " and " + advanced_filter

            top_genes_query += " group by hugo_symbol order by cnt desc limit 10"

            if project_id is not None:
                top_genes_data = DnaMutation.objects.using(settings.DB).raw(
                    top_genes_query
                )
                top_genes_name = [e.label for e in top_genes_data]
            else:
                top_genes_data = DnaMutation.objects.raw(top_genes_query)
                top_genes_name = [e.label for e in top_genes_data]

            dna_mutation_gene_query = "select 1 as id, dna.hugo_symbol as label,dna.variant_classification as vc,count(*) as count from dna_mutation as dna"

            if advanced_filter != "":
                dna_mutation_gene_query += " inner join clinical_information on dna.tumor_sample_barcode = clinical_information.pt_sbst_no"

            dna_mutation_gene_query += " where dna.variant_classification in " + \
                str(tuple(mutations))

            if len(top_genes_name) == 1:
                dna_mutation_gene_query += f" and dna.hugo_symbol = '{top_genes_name[0]}'"
            elif len(top_genes_name) > 1:
                dna_mutation_gene_query += " and dna.hugo_symbol in " + \
                    str(tuple(top_genes_name))

            if advanced_filter != "":
                dna_mutation_gene_query += " and " + advanced_filter

            dna_mutation_gene_query += " group by dna.hugo_symbol,dna.variant_classification order by count desc"

            if project_id is not None:
                dna_mutation_gene = DnaMutation.objects.using(settings.DB).raw(
                    dna_mutation_gene_query
                )
                top_genes = stack_data_generator(dna_mutation_gene, "")
            else:
                dna_mutation_gene = DnaMutation.objects.raw(
                    dna_mutation_gene_query)
                top_genes = stack_data_generator(dna_mutation_gene, "")

            tmp = {"datasets": [], "labels": top_genes_name}
            l = top_genes["labels"]
            for e in top_genes["datasets"]:
                g = {}
                d = e["data"]
                for i in range(0, len(l)):
                    g[l[i]] = d[i]
                e["data"] = [g[e] for e in top_genes_name]
                tmp["datasets"].append(e)

            top_genes = tmp
            # '''
            vc_summary_tmp = []

            if project_id is None:
                vc_summary_query = "select 1 as id,vc.variant_classification as label, array_agg(vc.count) as data from vc_summary as vc"
                if advanced_filter != "":
                    vc_summary_query += " inner join clinical_information on vc.tumor_sample_barcode = clinical_information.pt_sbst_no"
                vc_summary_query += " where vc.variant_classification in " + str(
                    tuple(mutations)
                )
                if advanced_filter != "":
                    vc_summary_query += " and " + advanced_filter
                vc_summary_query += " group by vc.variant_classification"
                vc_summary = DnaMutation.objects.raw(vc_summary_query)
            else:
                viewq = "SELECT count(*) AS count,dna_mutation.variant_classification,dna_mutation.tumor_sample_barcode FROM dna_mutation WHERE dna_mutation.variant_classification IN ('In_Frame_Del', 'In_Frame_Ins', 'Frame_Shift_Del', 'Frame_Shift_Ins', 'Nonsense_Mutation', 'Splice_Site', 'Germline', 'Missense_Mutation') GROUP BY dna_mutation.variant_classification, dna_mutation.tumor_sample_barcode ORDER BY dna_mutation.variant_classification DESC"
                vc_summary_query = f"Select 1 as id,vc.variant_classification as label, group_concat(vc.count,',') as data from ({viewq}) as vc "
                if advanced_filter != "":
                    vc_summary_query += " inner join clinical_information on vc.tumor_sample_barcode = clinical_information.pt_sbst_no"
                vc_summary_query += " where vc.variant_classification in " + str(
                    tuple(mutations)
                )
                if advanced_filter != "":
                    vc_summary_query += " and " + advanced_filter
                vc_summary_query += " group by vc.variant_classification"
                vc_summary = DnaMutation.objects.using(settings.DB).raw(
                    vc_summary_query
                )

            for e in vc_summary:
                d = [int(e) for e in e.data if e != ","]
                tmp = {"label": e.label, "data": d}
                vc_summary_tmp.append(tmp)

            res = {
                "Variant Classification": variant_rest_data.data,
                "Variant Type": variant_type_data.data,
                # "SNV Class": snv_data.data,
                "Top 10 Mutated Genes": top_genes,
                "Variant Classification Summary": vc_summary_tmp,
            }
            return Response(res, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class BrstRelations(APIView):
    def post(self, request):
        try:
            data = request.data
            filter_data = data.get("filter")
            project_id = data.get("project_id")
            advanse_filters_common_, advanse_params = "", []
            if project_id is None:
                if filter_data is not None and len(filter_data):
                    advanse_filters_common_, advanse_params = orm_filter_query_formater(
                        filter_data
                    )
                    if advanse_filters_common_ == False:
                        return Response(
                            {"message": "Unable to process the request"}, status=400
                        )

                query_orm = (
                    RnidDetails.objects.extra(
                        select={"id": 1, "rn_key": "rn_key",
                                "brst_key": "brst_key"},
                        tables=["clinical_information"],
                        where=["clinical_information.rnid=rnid.id"],
                    )
                    .distinct()
                    .values("id", "rn_key", "brst_key")
                )

                query_orm = query_orm.filter(
                    brst_key__isnull=False, rn_key__isnull=False
                )

                if advanse_filters_common_:
                    query_orm = query_orm.extra(
                        where=[advanse_filters_common_], params=advanse_params
                    )

                res = query_orm
            else:
                if filter_data is not None and len(filter_data):
                    (
                        advanse_filters_common_,
                        advanse_params,
                    ) = orm_advance_filter_query_formater(
                        filter_data, project_id=project_id
                    )
                    if advanse_filters_common_ == False:
                        return Response(
                            {"message": "Unable to process the request"}, status=400
                        )

                query_orm = (
                    ClinicalInformation.objects.using(settings.DB)
                    .extra(
                        select={
                            "id": 1,
                            "rn_key": "pt_sbst_no",
                            "brst_key": "pt_sbst_no",
                        }
                    )
                    .distinct()
                    .values("id", "rn_key", "brst_key")
                )
                if advanse_filters_common_:
                    query_orm = query_orm.extra(
                        where=[advanse_filters_common_], params=advanse_params
                    )

                res = query_orm

            brstReltaions = BrstRelationsSerializer(res, many=True)
            return Response(brstReltaions.data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class GetSamplesCount(APIView):
    def post(self, request):
        try:
            data = request.data
            if "project_id" in data:
                project_id = data["project_id"]
                project_information = UserDataProjects.objects.get(id=project_id)
                database_path = project_information.sql_path
                try:
                    project_database = {
                        "ENGINE": "django.db.backends.sqlite3",
                        "NAME": database_path,
                        "ATOMIC_REQUESTS": False,
                        "AUTOCOMMIT": True,
                        "CONN_MAX_AGE": 0,
                        "OPTIONS": {},
                        "TIME_ZONE": None,
                        "USER": "",
                        "PASSWORD": "",
                        "HOST": "",
                        "PORT": "",
                        "TEST": {
                            "CHARSET": None,
                            "COLLATION": None,
                            "MIGRATE": True,
                            "MIRROR": None,
                            "NAME": None,
                        },
                    }
                    settings.DATABASES["userdata"] = project_database
                    conn = sql.connect(database_path)
                    table_name = "clinical_information"
                    query = f"select count(pt_sbst_no) from {table_name}"
                    cursor = conn.execute(query)
                    result = cursor.fetchall()
                    return Response(
                        {"no_of_samples": result[0][0]}, status=status.HTTP_200_OK
                    )
                except:
                    result = 0
                    return Response(
                        {"no_of_samples": result}, status=status.HTTP_403_FORBIDDEN
                    )
            else:
                result = 0
                try:
                    result = (
                        ClinicalInformation.objects.values(
                            "pt_sbst_no").distinct().count()
                    )
                    return Response({"no_of_samples": result}, status=status.HTTP_200_OK)
                except:
                    return Response(
                        {"no_of_samples": result}, status=status.HTTP_403_FORBIDDEN
                    )
        except ObjectDoesNotExist as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class CircosPlot(APIView):
    def fusion_genes_data_serialize(self, fusion_data):
        fusion_genes_data = []
        for m in fusion_data:
            fusion_genes_data.append(
                {
                    "source": {
                        "id": m["left_gene_chr"],
                        "start": m["left_hg38_pos"] - 2000000,
                        "end": m["left_hg38_pos"] + 2000000,
                        "name": m["left_gene_name"],
                    },
                    "target": {
                        "id": m["right_gene_chr"],
                        "start": m["right_hg38_pos"] - 2000000,
                        "end": m["right_hg38_pos"] + 2000000,
                        "name": m["right_gene_name"],
                    },
                }
            )

        return fusion_genes_data

    def post(self, request):
        try:
            data = request.data
            project_id = data.get("project_id")

            constant_filter_data = filterBoxes

            if project_id is not None:
                project_id = project_id.strip()
                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="circos",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )
            if serializer.is_valid():
                # try:
                data = serializer.validated_data
                dna_mutation_query_orm = []
                rna_expression_query_orm = []
                dna_methylation_query_orm = []
                global_proteome_query_orm = []
                sv_query_orm = []
                cnv_query_orm = []
                fusion_genes_query_orm = []
                rnid = data.get("sampleKey")
                filter_data = data.get("filter")
                no_filters_limit = " limit 300"
                if project_id is not None:
                    available_steps = fetch_user_project_object(project_id)
                    available_steps_circos = available_steps.get("circos")

                advanse_filters_common, is_advanse_filters = "", False
                advanse_filters, advanse_filters_params = "", []
                if project_id is None and filter_data is not None and len(filter_data):
                    (
                        advanse_filters_common,
                        advanse_filters_params,
                        is_advanse_filters,
                    ) = orm_filter_query_formater(filter_data, circos=True)

                if project_id and filter_data is not None and len(filter_data):
                    (
                        advanse_filters_common,
                        advanse_filters_params,
                        is_advanse_filters,
                    ) = orm_advance_filter_query_formater(
                        filter_data, circos=True, project_id=project_id
                    )

                advanse_filters_common_without_genes = advanse_filters_common
                advanse_filters_common_without_genes_fusion = (
                    advanse_filters_common_without_genes
                )

                if project_id is None and len(filter_data):
                    advanse_filters, advanse_filters_params = orm_filter_query_formater(
                        data["filter"]
                    )

                if project_id and len(filter_data):
                    (
                        advanse_filters,
                        advanse_filters_params,
                        random_boolean
                    ) = orm_advance_filter_query_formater(
                        filter_data,
                        circos=True,
                        project_id=project_id
                    )
                    # RNA ORM Query - Done
                if (project_id and "rna" in available_steps_circos) or project_id is None:
                    try:
                        rna_expression_query_orm = (
                            (
                                Rna.objects.using(settings.DB).extra(
                                    select={
                                        "id": "1",
                                        "hugo_symbol": "rna.gene_name",
                                        "value": "rna.z_score",
                                        "chromosome": "hg38.chromosome",
                                        "start": "hg38.start_position",
                                        "end": "hg38.end_position",
                                    },
                                    tables=["rna", "hg38"],
                                    where=[
                                        "hg38.hugo_symbol = rna.gene_name",
                                        "rna.rnid IS NOT NULL",
                                    ],
                                )
                            )
                            .values("id", "hugo_symbol", "value", "chromosome", "start", "end")
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        error_message = "An error occurred while processing your request."
                        if isinstance(e, IntegrityError):
                            error_message = "An integrity error occurred while processing your request."
                            add_line_in_logger_file()
                            logger.exception(e)
                        return HttpResponseServerError(error_message)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")
                    # rna_expression_query_orm = rna_expression_query_orm.filter(
                    #     Q(z_score__lt=-1) | Q(z_score__gt=1)
                    # )

                    rna_expression_query_orm = rna_expression_query_orm.exclude(z_score=0)

                    if not rnid == "all" or rnid is None:
                        rna_expression_query_orm = rna_expression_query_orm.extra(
                            where=["rna.pt_sbst_no = %s"], params=[rnid]
                        )

                    if advanse_filters:
                        rna_expression_query_orm = rna_expression_query_orm.extra(
                            tables=["clinical_information"],
                            where=[f"rna.rnid=clinical_information.rnid",
                                advanse_filters],
                            params=advanse_filters_params,
                        )

                    if not "and" in str(rna_expression_query_orm.query).lower():
                        rna_expression_query_orm = rna_expression_query_orm[:300]

                # Methylation ORM Query - Done
                if (
                    project_id and "methylation" in available_steps_circos
                ) or project_id is None:
                    try:
                        dna_methylation_query_orm = (
                            Methylation.objects.using(settings.DB).extra(
                                select={
                                    "id": "1",
                                    "tumor_sample_barcode": "methylation.pt_sbst_no",
                                    "hugo_symbol": "methylation.gene_name",
                                    "value": "methylation.gene_vl",
                                    "chromosome": "hg38.chromosome",
                                    "start": "hg38.start_position",
                                    "end": "hg38.end_position",
                                },
                                tables=["hg38", "methylation"],
                                where=[
                                    "hg38.hugo_symbol = methylation.gene_name",
                                    "methylation.rnid IS NOT NULL",
                                ],
                            )
                        ).values(
                            "id",
                            "tumor_sample_barcode",
                            "hugo_symbol",
                            "value",
                            "chromosome",
                            "start",
                            "end",
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        error_message = "An error occurred while processing your request."
                        if isinstance(e, IntegrityError):
                            error_message = "An integrity error occurred while processing your request."
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError(error_message)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    dna_methylation_query_orm = dna_methylation_query_orm.filter(
                        ~Q(pt_sbst_no__isnull=True)
                    )

                    if rnid and rnid != "all":
                        dna_methylation_query_orm = dna_methylation_query_orm.extra(
                            where=["methylation.pt_sbst_no=%s"],
                            params=[rnid],
                        )

                    if advanse_filters:
                        dna_methylation_query_orm = dna_methylation_query_orm.extra(
                            where=[advanse_filters],
                            params=advanse_filters_params,
                            tables=["clinical_information"],
                        )

                # Proteome ORM Query - Done
                if (
                    project_id and "proteome" in available_steps_circos
                ) or project_id is None:
                    try:
                        global_proteome_query_orm = (
                            Proteome.objects.using(settings.DB).extra(
                                select={
                                    "id": "1",
                                    "value": "proteome.z_score",
                                    "chromosome": "hg38.chromosome",
                                    "hugo_symbol": "proteome.gene_name",
                                    "start": "hg38.start_position",
                                    "end": "hg38.end_position",
                                },
                                tables=["proteome", "hg38"],
                                where=[
                                    "hg38.hugo_symbol=proteome.gene_name",
                                    "proteome.rnid IS NOT NULL",
                                ],
                            )
                        ).values("id", "value", "chromosome", "hugo_symbol", "start", "end")
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        error_message = "An error occurred while processing your request."
                        if isinstance(e, IntegrityError):
                            error_message = "An integrity error occurred while processing your request."
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError(error_message)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    # global_proteome_query_orm = global_proteome_query_orm.filter(
                    #     Q(z_score__lt=0.5) | Q(z_score__gt=1.5)
                    # )
                    global_proteome_query_orm = global_proteome_query_orm.exclude(z_score=0)

                    if rnid and rnid != "all":
                        global_proteome_query_orm = global_proteome_query_orm.extra(
                            where=[
                                "proteome.pt_sbst_no=%s",
                            ],
                            params=[rnid],
                        )

                    if advanse_filters:
                        global_proteome_query_orm = global_proteome_query_orm.extra(
                            where=[advanse_filters],
                            params=advanse_filters_params,
                            tables=["clinical_information"],
                        )

                    if "and" not in str(global_proteome_query_orm.query).lower():
                        global_proteome_query_orm = global_proteome_query_orm[:300]

                #  Cnv ORM Query -Done
                if (project_id and "cnv" in available_steps_circos) or project_id is None:
                    try:
                        cnv_query_orm = (
                            Cnv.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "start_position": "start_pos",
                                    "end_position": "end_pos",
                                    "hugo_symbol": "gene",
                                    "genome_change": "cn",
                                    "chromosome": "chromosome",
                                },
                            )
                            .values(
                                "id",
                                "chromosome",
                                "start_position",
                                "end_position",
                                "hugo_symbol",
                                "genome_change",
                            )
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        error_message = "An error occurred while processing your request."
                        if isinstance(e, IntegrityError):
                            error_message = "An integrity error occurred while processing your request."
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError(error_message)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if rnid and rnid != "all":
                        if not project_id:
                            where_clause = f"cnv.r_fk_id=rnid.id and rnid.rn_key='{rnid}'"
                        elif project_id:
                            where_clause = f"cnv.rnid=rnid.id and rnid.rn_key='{rnid}'"

                    if where_clause:
                        cnv_query_orm = cnv_query_orm.extra(
                            tables=["rnid"],
                            where=[where_clause],
                        )

                    if project_id and is_advanse_filters:
                        cnv_query_orm = cnv_query_orm.extra(
                            tables=["clinical_information"],
                            where=["cnv.rnid=clinical_information.rnid"],
                        )

                    if not project_id and is_advanse_filters:
                        cnv_query_orm = cnv_query_orm.extra(
                            tables=["clinical_information"],
                            where=["cnv.r_fk_id=clinical_information.rnid"],
                        )

                    if advanse_filters_common_without_genes:
                        cnv_query_orm = cnv_query_orm.extra(
                            where=[advanse_filters_common_without_genes],
                            params=advanse_filters_params,
                        )
                    else:
                        cnv_query_orm = cnv_query_orm[:300]

                #  Dna Mutation ORM Query -Done
                if (
                    project_id and "dna_mutation" in available_steps_circos
                ) or project_id is None:
                    try:
                        dna_mutation_query_orm = (
                            DnaMutation.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "tumor_sample_barcode": "dna_mutation.tumor_sample_barcode",
                                    "chromosome": "dna_mutation.chromosome",
                                    "hugo_symbol": "dna_mutation.hugo_symbol",
                                    "start": "dna_mutation.start_position",
                                    "end": "dna_mutation.end_position",
                                    "value": "dna_mutation.gc_content",
                                }
                            )
                            .values(
                                "id",
                                "tumor_sample_barcode",
                                "chromosome",
                                "start",
                                "end",
                                "hugo_symbol",
                                "value",
                            )
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        error_message = "An error occurred while processing your request."
                        if isinstance(e, IntegrityError):
                            error_message = "An integrity error occurred while processing your request."
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError(error_message)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if advanse_filters:
                        dna_mutation_query_orm = dna_mutation_query_orm.extra(
                            tables=["clinical_information"],
                            where=[
                                f"dna_mutation.rnid=clinical_information.rnid",
                                advanse_filters,
                            ],
                            params=advanse_filters_params,
                        )

                    dna_mutation_query_orm = dna_mutation_query_orm.extra(
                        where=["dna_mutation.rnid IS NOT NULL"]
                    )

                    if rnid and rnid != "all":
                        dna_mutation_query_orm = dna_mutation_query_orm.filter(
                            tumor_sample_barcode=rnid
                        )
                    dna_mutation_query_orm = dna_mutation_query_orm.order_by(
                        "chromosome")

                #  SV ORM Query -Done
                if (
                    project_id and "dna_mutation" in available_steps_circos
                ) or project_id is None:
                    try:
                        sv_query_orm = (
                            DnaMutation.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "left_gene_chr": "chromosome",
                                    "left_gene_pos": "start_position",
                                    "right_gene_chr": "chromosome",
                                    "right_gene_pos": "end_position",
                                    "left_gene_name": "hugo_symbol",
                                    "right_gene_name": "hugo_symbol",
                                    "svtype": "(CASE WHEN variant_type = 'INS' THEN 'Insertion' ELSE 'Deletion' END)",
                                },
                                tables=["dna_mutation"],
                                where=["variant_type in ('DEL', 'INS')"],
                            )
                            .values(
                                "id",
                                "left_gene_chr",
                                "left_gene_pos",
                                "right_gene_chr",
                                "right_gene_pos",
                                "left_gene_name",
                                "right_gene_name",
                                "svtype",
                            )
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        error_message = "An error occurred while processing your request."
                        if isinstance(e, IntegrityError):
                            error_message = "An integrity error occurred while processing your request."
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError(error_message)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    sv_query_orm = sv_query_orm.extra(
                        where=[f"dna_mutation.tumor_sample_barcode = '{rnid}'"]
                    )

                # Fusion ORM Query -Done

                if (
                    project_id and "fusion" in available_steps_circos
                ) or project_id is None:
                    try:
                        fusion_genes_query_orm = (
                            Fusion.objects.using(settings.DB).extra(
                                select={
                                    "id": "1",
                                    "left_gene_chr": "fusion.left_gene_chr",
                                    "right_gene_chr": "fusion.right_gene_chr",
                                    "left_gene_name": "fusion.left_gene_name",
                                    "right_gene_name": "fusion.right_gene_name",
                                    "left_hg38_pos": "fusion.left_hg38_pos",
                                    "right_hg38_pos": "fusion.right_hg38_pos",
                                },
                            )
                        ).values(
                            "id",
                            "left_gene_chr",
                            "right_gene_chr",
                            "left_gene_name",
                            "right_gene_name",
                            "left_hg38_pos",
                            "right_hg38_pos",
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        error_message = "An error occurred while processing your request."
                        if isinstance(e, IntegrityError):
                            error_message = "An integrity error occurred while processing your request."
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError(error_message)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if is_advanse_filters:
                        fusion_genes_query_orm = fusion_genes_query_orm.extra(
                            tables=["clinical_information"],
                            where=["fusion.rnid=clinical_information.rnid"],
                        )
                    if rnid is not None and rnid != "all":
                        fusion_genes_query_orm = fusion_genes_query_orm.extra(
                            tables=["rnid"], where=["fusion.rnid=rnid.id", f"rnid.rn_key='{rnid}'"]
                        )

                    fusion_genes_query_orm = fusion_genes_query_orm.extra(
                        where=["fusion.rnid is not NULL"]
                    )

                    if advanse_filters_common_without_genes_fusion:
                        fusion_genes_query_orm = fusion_genes_query_orm.extra(
                            where=[advanse_filters_common_without_genes],
                            params=advanse_filters_params,
                        )

                    if rnid == "all" and "limit" not in fusion_genes_query_orm.query:
                        fusion_genes_query_orm = fusion_genes_query_orm.extra(
                            select={"limit": "'{}'"}, select_params=[no_filters_limit]
                        )

                # ==================================== #
                res = {}
                res["dna_mutation"] = dna_mutation_query_orm

                res["rna_expression"] = rna_expression_query_orm

                res["dna_methylation"] = dna_methylation_query_orm

                res["global_proteome"] = global_proteome_query_orm

                res["sv_data"] = sv_query_orm

                res["cnv"] = cnv_query_orm

                fusion_genes_data = self.fusion_genes_data_serialize(
                    fusion_genes_query_orm)
                res["fusion_genes_data"] = fusion_genes_data

                is_no_content_response = True
                for _, val in res.items():
                    if len(val) > 0:
                        is_no_content_response = False
                if is_no_content_response:
                    res = {
                        "rna_expression": [],
                        "dna_methylation": [],
                        "global_proteome": [],
                        "dna_mutation": [],
                        "cnv": [],
                        "sv_data": [],
                        "fusion_genes_data": [],
                    }
                    return Response(res, status=204)
                return Response(res, status=200)
            else:
                return Response({"message": "Unable to process the requests"}, status=400)
        except ObjectDoesNotExist as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class OncoPrintPlot(APIView):
    def post(self, request):
        try:
            data = request.data
            project_id = data.get("project_id")
            genes = data.get("genes")
            constant_filter_data = filterBoxes
            tabs=[]
            z_score_up_prot= 1.5
            z_score_down_prot= 0.5
            z_score_up_rna= 1
            z_score_down_rna= -1
            cn_up_value= 3
            cn_equal_value= 2
            cn_down_value= 1

            if data.get("z_score_up_prot"):
                z_score_up_prot = data.get("z_score_up_prot")
            if data.get("z_score_down_prot"):
                z_score_down_prot=data.get("z_score_down_prot")
            if data.get("z_score_down_rna"):
                z_score_down_rna=data.get("z_score_down_rna")
            if data.get("z_score_up_rna"):
                z_score_up_rna=data.get("z_score_up_rna")
            if data.get("cn_up_value"):
                cn_up_value=data.get("cn_up_value")
            if data.get("cn_equal_value"):
                cn_equal_value=data.get("cn_equal_value")
            if data.get("cn_down_value"):
                cn_down_value=data.get("cn_down_value")


            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="oncoprint",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )

            res = {}
            if serializer.is_valid() and len(genes) > 0:
                data = serializer.validated_data
                genes = data.get("genes")
                filters = data.get("filter")
                advanse_filters_ = ""
                advanse_params = []
                if len(filters):
                    if project_id is None:
                        advanse_filters_, advanse_params = orm_filter_query_formater(
                            filters
                        )
                    elif project_id:
                        (
                            advanse_filters_,
                            advanse_params,
                        ) = orm_advance_filter_query_formater(filters, False, project_id)
                clinicalFilters = []
                if "clinicalFilters" in data:
                    clinicalFilters = data["clinicalFilters"]
                    if not isinstance(clinicalFilters, list):
                        return Response({}, status=204)
                #'''
                try:
                    query_orm = (
                        DnaMutation.objects.using(settings.DB)
                        .values("variant_classification", "tumor_sample_barcode")
                        .annotate(
                            cnt=Count("variant_classification"),
                            sample=F("tumor_sample_barcode"),
                        )
                        .values("cnt", "variant_classification", "sample")
                    )
                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")

                if advanse_filters_ != "":
                    query_orm = query_orm.extra(
                        tables=["clinical_information"],
                        where=["dna_mutation.rnid = clinical_information.rnid"],
                    )

                query_orm = query_orm.filter(
                    variant_classification__in=dna_mutation_variant_classifications_list,
                    variant_classification__isnull=False,
                )

                if advanse_filters_ != "":
                    query_orm = query_orm.extra(
                        where=[advanse_filters_], params=advanse_params
                    )
                global_mutations_res_ = query_orm
                globalMutCategory_tmp = {}
                get_samples = []
                global_mut_cnt = {}

                #'''
                for e in global_mutations_res_:
                    if e["sample"] in globalMutCategory_tmp:
                        globalMutCategory_tmp[e["sample"]][e["variant_classification"]] = (
                            globalMutCategory_tmp[e["sample"]
                                                ][e["variant_classification"]]
                            + e["cnt"]
                        )
                    else:
                        globalMutCategory_tmp[e["sample"]] = {
                            "In_Frame_Ins": 0,
                            "Frame_Shift_Del": 0,
                            "Frame_Shift_Ins": 0,
                            "Missense_Mutation": 0,
                            "Nonsense_Mutation": 0,
                            "Splice_Site": 0,
                            "In_Frame_Del": 0,
                            "Germline": 0,
                        }
                        globalMutCategory_tmp[e["sample"]][e["variant_classification"]] = e[
                            "cnt"
                        ]

                    if e["sample"] not in get_samples:
                        get_samples.append(e["sample"])
                    if e["sample"] in global_mut_cnt:
                        global_mut_cnt[e["sample"]
                                    ] = global_mut_cnt[e["sample"]] + e["cnt"]
                    else:
                        global_mut_cnt[e["sample"]] = e["cnt"]

                globalMutCnt = [{"cnt": v, "sample": k}
                                for k, v in global_mut_cnt.items()]
                globalMutCategory = [
                    {"val": v, "sample": k} for k, v in globalMutCategory_tmp.items()
                ]

                check_table_exist = ""
                check_table_exist_dna = ""
                check_table_exist_rna = ""
                check_table_exist_proteome = ""
                check_table_exist_cnv = ""
                check_table_exist_fusion = ""
                table_types = []
                if project_id is None:
                    table_types.extend(['rna', 'dna', 'proteome', 'cnv', 'fusion'])
                else:
                    table_types=[]

                if project_id:
                    table_query = "select 1 as id,name from sqlite_master where type='table' and name='dna_mutation'"
                    check_table_exist_dna = Rna.objects.using(
                        settings.DB).raw(table_query)

                if check_table_exist_dna or project_id is None:
                    try:
                        query_orm = (
                            DnaMutation.objects.using(settings.DB)
                            .values("variant_classification", "tumor_sample_barcode")
                            .annotate(sample=F("tumor_sample_barcode"))
                            .values("variant_classification", "sample")
                            .annotate(cnt=Count("*"))
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")
                #'''
                if advanse_filters_ != "":
                    query_orm = query_orm.extra(
                        tables=["clinical_information"],
                        where=["dna_mutation.rnid = clinical_information.rnid"],
                    )
                    query_orm = query_orm.extra(
                        where=[advanse_filters_], params=advanse_params
                    )

                #'''
                if len(genes) == 1:
                    query_orm = query_orm.filter(
                        variant_classification__in=dna_mutation_variant_classifications_list,
                        hugo_symbol=genes[0],
                    )
                else:
                    query_orm = query_orm.filter(
                        variant_classification__in=dna_mutation_variant_classifications_list,
                        hugo_symbol__in=genes,
                    )

                dna_mutation = query_orm
                MutCategory_tmp = {}
                mut_cnt = {}
                mut_samples = []
                for e in dna_mutation:
                    if e["sample"] not in get_samples:
                        get_samples.append(e['sample'])
                    if e["sample"] not in mut_samples:
                        mut_samples.append(e["sample"])

                    if e["sample"] in MutCategory_tmp:
                        MutCategory_tmp[e["sample"]][e["variant_classification"]] = (
                            MutCategory_tmp[e["sample"]
                                            ][e["variant_classification"]]
                            + e["cnt"]
                        )
                    else:
                        MutCategory_tmp[e["sample"]] = {
                            "In_Frame_Ins": 0,
                            "Frame_Shift_Del": 0,
                            "Frame_Shift_Ins": 0,
                            "Missense_Mutation": 0,
                            "Nonsense_Mutation": 0,
                            "Splice_Site": 0,
                            "In_Frame_Del": 0,
                            "Germline": 0,
                        }
                        MutCategory_tmp[e["sample"]
                                        ][e["variant_classification"]] = e["cnt"]

                    if e["sample"] in mut_cnt:
                        mut_cnt[e["sample"]] = mut_cnt[e["sample"]] + e["cnt"]
                    else:
                        mut_cnt[e["sample"]] = e["cnt"]

                MutCategory = [{"val": v, "sample": k}
                            for k, v in MutCategory_tmp.items()]
                mutCnt = [{"cnt": v, "sample": k} for k, v in mut_cnt.items()]



                clinicalData = {
                    "globalMutCategory": globalMutCategory,
                    "mutCategory": MutCategory,
                    "globalMutCnt": globalMutCnt,
                    "mutCnt": mutCnt,
                    'custom':[]
                }


                #'''
                if project_id:
                    table_query = "select 1 as id,name from sqlite_master where type='table' and name='dna_mutation'"

                    try:
                        check_table_exist_dna = Rna.objects.using(
                            settings.DB).raw(table_query)
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                if check_table_exist_dna or project_id is None:
                    try:
                        query_res = (
                            DnaMutation.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "gene": "hugo_symbol",
                                    "sample": "tumor_sample_barcode",
                                    "variant_classification": "variant_classification",
                                }
                            )
                            .values("id", "gene", "sample", "variant_classification")
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")
                #'''
                if advanse_filters_ != "":
                    query_res = query_res.extra(
                        tables=["clinical_information"],
                        where=["dna_mutation.rnid = clinical_information.rnid"],
                    )

                query_res = query_res.filter(
                    variant_classification__in=dna_mutation_variant_classifications_list
                )

                if len(genes) == 1:
                    query_res = query_res.filter(hugo_symbol=genes[0])
                else:
                    query_res = query_res.filter(hugo_symbol__in=genes)

                #'''
                if advanse_filters_ != "":
                    query_res = query_res.extra(
                        where=[advanse_filters_], params=advanse_params
                    )
                dna_data = []

                dna_data = query_res
                dna_res = {}
                for each in dna_data:
                    if each['sample'] not in get_samples:
                        get_samples.append(each["sample"])
                    dna_res[each["sample"] + "||" + each["gene"]]= each["variant_classification"]

                if project_id:

                    table_query = "select 1 as id,name from sqlite_master where type='table' and name='rna'"
                    try:
                        check_table_exist_rna = Rna.objects.using(
                            settings.DB).raw(table_query)
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                if check_table_exist_rna or project_id is None:
                    if 'rna' not in table_types:
                        table_types.append('rna')
                    try:
                        query_res = (
                            Rna.objects.using(settings.DB)
                            .annotate(
                                gene=F("gene_name"),
                                sample=F("pt_sbst_no"),
                                regulation=Case(
                                    When(z_score__gte=z_score_up_rna, then=Value("up")),
                                    When(z_score__lte=z_score_down_rna, then=Value("down")),
                                    output_field=CharField(),
                                ),
                            )
                            .filter(type='T')
                            .exclude(regulation=None)
                            .values("id", "gene", "z_score", "regulation", "sample")
                            .distinct()
                        )

                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                #'''
                    if advanse_filters_ != "":
                        query_res = query_res.extra(
                            tables=["clinical_information"],
                            where=["clinical_information.rnid = rna.rnid"],
                        )
                    #'''
                    if len(genes) == 1:
                        query_res = query_res.filter(gene_name=genes[0])
                    else:
                        query_res = query_res.filter(gene_name__in=genes)

                    query_res = query_res.filter(Q(z_score__gt=1) | Q(z_score__lt=-1))

                    #'''
                    if advanse_filters_ != "":
                        query_res = query_res.extra(
                            where=[advanse_filters_], params=advanse_params
                        )

                    rna_data = []
                    rna_data = query_res
                    rna_res = {}
                    for g in rna_data:
                        if g['sample'] not in get_samples:
                            get_samples.append(g["sample"])
                        rna_res[g["sample"] + "||" + g["gene"]] = g["regulation"]

                if project_id:

                    table_query = "select 1 as id,name from sqlite_master where type='table' and name='proteome'"
                    try:
                        check_table_exist_proteome = Rna.objects.using(
                            settings.DB).raw(table_query)
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                if check_table_exist_proteome or project_id is None:
                    if 'proteome' not in table_types:
                        table_types.append('proteome')
                    try:
                        query_res = (
                            Proteome.objects.using(settings.DB)
                            .annotate(
                                regulation=Case(
                                    When(z_score__gte=z_score_up_prot, then=Value("up")),
                                    When(z_score__lte=z_score_down_prot, then=Value("down")),
                                    output_field=CharField(),
                                ),
                                gene=F("gene_name"),
                                sample=F("pt_sbst_no"),
                            )
                            .filter(type='T')
                            .values("gene", "sample", "regulation")
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if advanse_filters_ != "":
                        query_res = query_res.extra(
                            tables=["clinical_information"],
                            where=["clinical_information.rnid = proteome.rnid"],
                        )

                    #'''
                    if len(genes) == 1:
                        query_res = query_res.filter(gene_name=genes[0])
                    else:
                        query_res = query_res.filter(gene_name__in=genes)

                    query_res = query_res.filter(Q(z_score__gt=z_score_up_prot) | Q(z_score__lt=-z_score_down_prot))

                    if advanse_filters_ != "":
                        query_res = query_res.extra(
                            where=[advanse_filters_], params=advanse_params
                        )

                    proteome_data = []

                    proteome_data = query_res
                    protein_res = {}
                    for g in proteome_data:
                        if g['sample'] not in get_samples:
                            get_samples.append(g["sample"])
                        protein_res [g["sample"] + "||" + g["gene"]] = g["regulation"]
                if project_id:

                    table_query = "select 1 as id,name from sqlite_master where type='table' and name='cnv'"
                    try:
                        check_table_exist_cnv = Rna.objects.using(
                            settings.DB).raw(table_query)
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")


                if check_table_exist_cnv or project_id is None:
                    if 'cnv' not in table_types:
                        table_types.append('cnv')
                    try:
                        query_res = (
                            Cnv.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "gene": "cnv.gene",
                                    "sample": "rnid.rn_key",
                                    "cn": f"CASE when cnv.cn >={cn_up_value} then 'purple' when cnv.cn ={cn_equal_value} then 'blue' WHEN cnv.cn<={cn_down_value} then 'red' END",
                                    "hugo_symbol": "dna_mutation.hugo_symbol",
                                },
                                tables=["rnid", "dna_mutation"],
                                where=["rnid.id = cnv.r_fk_id",
                                    "dna_mutation.rnid=cnv.r_fk_id"]
                                if project_id is None
                                else ["rnid.id = cnv.rnid", "dna_mutation.rnid=cnv.rnid"],
                            )
                            .values("id", "gene", "sample", "cn")
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if project_id is None and advanse_filters_ != "":
                        query_res = query_res.extra(
                            tables=["clinical_information"],
                            where=["clinical_information.rnid = cnv.r_fk_id"],
                        )
                    if project_id is not None and advanse_filters_ != "":
                        query_res = query_res.extra(
                            tables=["clinical_information"],
                            where=["clinical_information.rnid = cnv.rnid"],
                        )
                if check_table_exist_cnv or project_id is None:
                    if len(genes) == 1:
                        query_res = query_res.extra(
                            where=[
                                f"cnv.gene = '{genes[0]}'",
                                f"dna_mutation.hugo_symbol = '{genes[0]}'",
                            ]
                        )
                    else:
                        query_res = query_res.extra(
                            where=[
                                f"cnv.gene in {tuple(genes)}",
                                f"dna_mutation.hugo_symbol in {tuple(genes)}",
                            ]
                        )

                    query_res = query_res.extra(
                        where=[
                            f"dna_mutation.variant_classification in {tuple(dna_mutation_variant_classifications_list)}"
                        ]
                    )

                    if advanse_filters_ != "":
                        query_res = query_res.extra(
                            where=[advanse_filters_], params=advanse_params
                        )

                    cnv_data = []
                    cnv_data = query_res
                    cnv_res = {}
                    for g in cnv_data:
                        if g['sample'] not in get_samples:
                            get_samples.append(g["sample"])
                        cnv_res[g["sample"] + "||" + g["gene"]] =  g["cn"]

                if project_id:
                    table_query = "select 1 as id,name from sqlite_master where type='table' and name='fusion'"
                    try:
                        check_table_exist_fusion = Rna.objects.using(
                            settings.DB).raw(table_query)
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                if check_table_exist_fusion or project_id is None:
                    try:
                        query_res = (
                            Fusion.objects.using(settings.DB)
                            .all()
                            .extra(
                                select={
                                    "id": "fusion.id",
                                    "left_gene_name": "left_gene_name",
                                    "right_gene_name": "right_gene_name",
                                    "sample": "rnid.id",
                                },
                                tables=["rnid"],
                                where=["fusion.rnid = rnid.id"],
                            )
                            .values("id", "left_gene_name", "right_gene_name", "sample")
                        )

                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if advanse_filters_ != "":
                        query_res = query_res.extra(
                            tables=["clinical_information"],
                            where=["clinical_information.rnid = fusion.rnid"],
                        )
                    if advanse_filters_ != "":
                        query_res = query_res.extra(
                            where=[advanse_filters_], params=advanse_params
                        )

                    if len(genes) == 1:
                        query_res = query_res.filter(
                            left_gene_name=genes[0], right_gene_name=genes[0]
                        )
                    else:
                        query_res = query_res.filter(
                            left_gene_name__in=genes, right_gene_name__in=genes
                        )

                    fusion_data = []

                    fusion_data = query_res

                    fusion_res = {}
                    for g in fusion_data:
                        if g['sample'] not in get_samples:
                            get_samples.append(g["sample"])
                        if g["left_gene_name"] in genes:
                            fusion_res[str(g["sample"]) + "||" + g["left_gene_name"]] = "true"
                        elif g["right_gene_name"] in genes:
                            fusion_res[str(g["sample"]) + "||" +
                                    g["right_gene_name"]] = "true"
                genes_list = []
                if project_id is not None:
                    if not check_table_exist_cnv:
                        cnv_res = {}
                    if not check_table_exist_fusion:
                        fusion_res = {}
                    if not check_table_exist_rna:
                        rna_res = {}
                    if not check_table_exist_proteome:
                        protein_res = {}
                for gene in genes:
                    tmp_list = {
                        "gene": gene,
                        "desc": gene,
                    }
                    t = []

                    for sample in get_samples:
                        tmp = {"sample": sample}
                        if sample in mut_samples:
                            name = sample + "||" + gene
                            if name in dna_res:
                                tmp["variant_classification"] = dna_res[name]
                            if name in rna_res:
                                tmp["regulation"] = rna_res[name]
                            if name in protein_res:
                                tmp["protein"] = protein_res[name]
                            if name in cnv_res:
                                tmp["cnv"] = cnv_res[name]
                            if name in fusion_res:
                                tmp["fusion"] = fusion_res[name]
                        t.append(tmp)
                    tmp_list["data"] = t
                    genes_list.append(tmp_list)
                custom_fields = [
                    "ki67_score",
                    "her2_score",
                    "t_category",
                    "n_category",
                    "bmi_vl",
                    "mena_age",
                    "feed_drtn_mnth",
                    "diag_age",
                    "rlps_cnfr_drtn",
                ]
                custom = []
                custom_category = {}
                _filter_json_columns = {}

                if project_id is not None:
                    d = FilterJson(request=request._request)
                    _filter_json = d.post(request)
                    project_filters = _filter_json.data
                    if (
                        project_filters
                        and "filterJson" in project_filters
                        and "Clinical Information" in project_filters["filterJson"]
                    ):
                        _project_filters = project_filters["filterJson"][
                            "Clinical Information"
                        ]
                        for k, v in _project_filters.items():
                            _type = v[0]["type"]
                            if _type == "checkbox":
                                if (v[0]["value"] == "yes") or (v[0]["value"] == "no"):
                                    _filter_json_columns[k] = "bool"
                                else:
                                    _filter_json_columns[k] = "text"

                if clinicalFilters and len(clinicalFilters) > 0:
                    feed_mnth = {"1~4": 0, "5~8": 0, "9~12": 0, "13~": 0, "N/A": 0}
                    ki67_tx = {"~ 15": [0, 15], "16 ~ 30": [
                        16, 30], "31 ~": [31, 100]}
                    ki67_t = ["~ 15", "16 ~ 30", "31 ~"]
                    feed_b = {
                        0: "1~4",
                        1: "1~4",
                        2: "1~4",
                        3: "1~4",
                        4: "1~4",
                        5: "5~8",
                        6: "5~8",
                        7: "5~8",
                        8: "5~8",
                        9: "9~12",
                        10: "9~12",
                        11: "9~12",
                        12: "9~12",
                        13: "13~",
                    }

                    for fields in clinicalFilters:
                        if project_id:
                            try:
                                query_res_ = (
                                    ClinicalInformation.objects.using(settings.DB)
                                    .extra(
                                        select={
                                            "id": "1",
                                            "pt_sbst_no": "pt_sbst_no",
                                            fields: fields,
                                        }
                                    )
                                    .values("id", "pt_sbst_no", fields)
                                )
                            except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("A database-related error occurred while processing your request.")
                            except Exception as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("An error occurred while processing your request.")
                            query_res_ = query_res_.extra(
                                tables=["dna_mutation"],
                                where=["dna_mutation.rnid=clinical_information.rnid"],
                            ).order_by("-pt_sbst_no")

                        else:
                            if fields in oncoqueries:
                                try:
                                    query_res_ = ClinicalInformation.objects.values(
                                        "id", "pt_sbst_no", *oncoqueries[fields]
                                    ).distinct()
                                    query_res_ = query_res_.extra(
                                        tables=["dna_mutation"],
                                        where=[
                                            "dna_mutation.rnid=clinical_information.rnid"],
                                    ).order_by("-pt_sbst_no")
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")

                            elif fields in onco_cusotom_queries:
                                if fields == "er_score":
                                    my_dict = {
                                        "c_er_score": Case(
                                            When(er_score="1",
                                                    then=Value("Positive")),
                                            When(er_score="2",
                                                    then=Value("Negative")),
                                            output_field=CharField(),
                                        )
                                    }
                                elif fields == "pr_score":
                                    my_dict = {
                                        "c_pr_score": Case(
                                            When(er_score="1",
                                                    then=Value("Positive")),
                                            When(er_score="2",
                                                    then=Value("Negative")),
                                            output_field=CharField(),
                                        )
                                    }
                                try:
                                    query_res__ = ClinicalInformation.objects.values(
                                        "id", "pt_sbst_no", **my_dict
                                        ).distinct()
                                    query_res__ = query_res__.extra(
                                        tables=["dna_mutation"],
                                        where=[
                                            "dna_mutation.rnid=clinical_information.rnid"],
                                    ).order_by("-pt_sbst_no")
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")
                                if fields == "er_score":
                                    query_res_ = [
                                        {
                                            "er_score" if k == "c_er_score" else k: v
                                            for k, v in obj.items()
                                        }
                                        for obj in query_res__
                                    ]
                                elif fields == "pr_score":
                                    query_res_ = [
                                        {
                                            "pr_score" if k == "c_pr_score" else k: v
                                            for k, v in obj.items()
                                        }
                                        for obj in query_res__
                                    ]
                            else:
                                try:
                                    query_res_ = (
                                        ClinicalInformation.objects.extra(
                                            select={
                                                "id": "1",
                                                "pt_sbst_no": "pt_sbst_no",
                                                fields: fields,
                                            }
                                        )
                                        .values("id", "pt_sbst_no", fields)
                                        .distinct()
                                    )
                                    query_res_ = query_res_.extra(
                                        tables=["dna_mutation"],
                                        where=[
                                            "dna_mutation.rnid=clinical_information.rnid"],
                                    ).order_by("-pt_sbst_no")
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")

                        filter_query_data = query_res_


                        tmp_samples = []
                        ix = 1
                        for z_row in filter_query_data:
                            r = z_row
                            ix = ix+1
                            if r["pt_sbst_no"] in get_samples:
                                tmp_name = fields + "||" + r["pt_sbst_no"]
                                if tmp_name not in custom_category:
                                    if project_id is not None:
                                        custom_category[tmp_name] = r[fields]
                                    else:
                                        if fields in oncoqueries:
                                            tmp_l = []
                                            for f in oncoqueries[fields]:
                                                if r[f] is None:
                                                    tmp_l.append("N/A")
                                                else:
                                                    val = r[f]
                                                    if isinstance(val, int):
                                                        val = str(int(val))
                                                    elif isinstance(val, float):
                                                        val = str(int(float(val)))

                                                    tmp_l.append(val)
                                            custom_category[tmp_name] = "||".join(
                                                tmp_l)
                                        else:
                                            custom_category[tmp_name] = r[fields]

                        t = {}
                        t["displayName"] = fields
                        t["data"] = []
                        for k, v in custom_category.items():
                            row = k.split("||")
                            if project_id is not None:
                                if row[0] == fields and v is not None:
                                    if _filter_json_columns[fields] == "bool":
                                        tmp = ""
                                        if v == True:
                                            tmp = "yes"

                                        elif v == False:
                                            tmp = "no"

                                        else:
                                            tmp = "NA"

                                        t["data"].append(
                                            {"sample": row[1], "category": tmp}
                                        )
                                    else:
                                        t["data"].append(
                                            {
                                                "sample": row[1],
                                                "category": v if v != "" else "NA",
                                            }
                                        )

                            else:
                                if row[0] == fields and v is not None:

                                    if fields == "diag_age":
                                        tmp = ""
                                        if v > 20 and v <= 25:
                                            tmp = "21~25"
                                        elif v > 25 and v <= 30:
                                            tmp = "26~30"
                                        elif v > 30 and v <= 35:
                                            tmp = "31~35"
                                        elif v > 35 and v <= 40:
                                            tmp = "36~40"
                                        t["data"].append(
                                            {"sample": row[1], "category": tmp}
                                        )
                                    elif fields == "bmi_vl":
                                        tmp = "N/A"
                                        if v < 18.5:
                                            tmp = "~18.5"
                                        elif v > 18.5 and v <= 25:
                                            tmp = "18.6 ~ 25"
                                        elif v > 25 and v <= 30:
                                            tmp = "25.1~30"
                                        elif v > 30:
                                            tmp = "30.1~"

                                        t["data"].append(
                                            {"sample": row[1], "category": tmp}
                                        )
                                    elif fields == "smok_curr_yn":
                                        smok_curr_yn = v.split("||")
                                        tmp = ""
                                        if smok_curr_yn[0] == "1":
                                            if not smok_curr_yn[1] == "0":
                                                tmp = "past smoking"
                                        elif smok_curr_yn[0] == "0":
                                            tmp = "non smoking"

                                        if smok_curr_yn[1] == "1":
                                            tmp = "current smoking"
                                        if tmp == "":
                                            tmp = "N/A"
                                        t["data"].append(
                                            {"sample": row[1], "category": tmp}
                                        )
                                    elif fields == "feed_drtn_mnth":
                                        time = v.split("||")
                                        totalmonths = 0
                                        if time[0].isnumeric():
                                            totalmonths = int(time[0]) * 12
                                        if time[1].isnumeric():
                                            totalmonths = totalmonths + \
                                                int(time[1])

                                        tmp = ""
                                        if time[0].isnumeric() or time[1].isnumeric():
                                            if totalmonths <= 12:
                                                tmp = "<=1Year"
                                            else:
                                                tmp = ">1Year"
                                        else:
                                            tmp = "N/A"
                                        t["data"].append(
                                            {"sample": row[1], "category": tmp}
                                        )
                                    elif fields == "ki67_score":
                                        tmp = ""
                                        if v <= 15:
                                            tmp = "low"
                                        elif v > 15 and v <= 30:
                                            tmp = "intermediate"
                                        elif v > 30:
                                            tmp = "high"

                                        else:
                                            tmp = v

                                        t["data"].append(
                                            {"sample": row[1], "category": tmp}
                                        )

                                    elif (
                                        fields == "bila_cncr_yn"
                                        or fields == "drnk_yn"
                                        or fields == "fmhs_brst_yn"
                                        or fields == "oc_yn"
                                        or fields == "meno_yn"
                                        or fields == "delv_yn"
                                        or fields == "feed_yn"
                                        or fields == "hrt_yn"
                                        or fields == "rlps_yn"
                                    ):
                                        tmp = ""
                                        if v == True:
                                            tmp = "yes"

                                        elif v == False:
                                            tmp = "no"

                                        else:
                                            tmp = "NA"

                                        t["data"].append(
                                            {"sample": row[1], "category": tmp}
                                        )

                                    else:
                                        t["data"].append(
                                            {
                                                "sample": row[1],
                                                "category": v if v != "" else "NA",
                                            }
                                        )

                        custom.append(t)

                    tmp = []
                    for e in reversed(clinicalFilters):
                        for i in custom:
                            if i["displayName"] == e:
                                tmp.append(i)
                    custom = tmp
                    clinicalData['custom'] = custom
                res = {"geneData": genes_list, "clinicalData": clinicalData,'types':table_types}

            return Response(res, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class FusionVenn(APIView):
    def get_group_filter_details(self, clinical_filters):
        database_column = clinical_filters.get("column")
        clinical_filters.pop("column", None)
        filter_type = clinical_filters.get("type")
        clinical_filters.pop("type", None)
        filter_keys = list(clinical_filters.keys())
        total_groups = set()

        if filter_type == "static":
            i = 1
            for key in filter_keys:
                total_groups.add(i)
                i = i + 1
        elif filter_type == "number":
            for key in filter_keys:
                total_groups.add(int(key.split("_")[0]))
        elif filter_type == "text":
            if database_column == "her2_score":
                for key in filter_keys:
                    total_groups.add(int(key.split("_")[0]))
            else:
                for key in filter_keys:
                    total_groups.add(int(key))

        return {"column": database_column, "groups": total_groups, "type": filter_type}

    def orm_generate_query_for_filter(
        self,
        boolean=None,
        text=None,
        from_range=None,
        to_range=None,
        column=None,
        filter_group=None,
        viz_filter_type=None,
        project_id=None,
    ):
        query_orm = (
            Fusion.objects.using(settings.DB)
            .extra(
                select={"id": "fusion.rnid"},
                tables=["clinical_information"],
                where=["clinical_information.rnid=fusion.rnid"],
            )
            .values("id")
            .distinct()
        )

        if boolean is not None:
            if project_id is None:
                boo_str = "Y" if boolean == True else "N"
                if boolean == True:
                    query_orm = query_orm.extra(where=[f"({column} = 'Y')"])
                else:
                    query_orm = query_orm.extra(where=[f"({column} != 'Y')"])
            else:
                boo_str = 1 if boolean == True else 0
                query_orm = query_orm.extra(
                    where=[f"({column} = %s)"], params=[str(boo_str)]
                )

        elif text is not None:
            if project_id is None:
                if column == "smok_yn":
                    value = text[0].split("||")[1]
                    col = text[0].split("||")[0]
                    query_orm = query_orm.extra(where=[f"({col} = '{value}')"])
                elif column == "t_category" or column == "n_category":
                    t = "','".join(text)
                    query_orm = query_orm.extra(where=[f"{column} IN ('{t}')"])

                elif column == "her2_score":
                    t_values = []
                    for ei in text:
                        t_values.extend(dynamic_her2[ei])
                    t_values = list(set(t_values))
                    t_values_str = "','".join(str(n) for n in t_values)
                    query_orm = query_orm.extra(
                        where=[f"{column} IN ('{t_values_str}')"])

                elif column == "ki67_score":
                    t_values = []
                    for ei in text:
                        t_values.extend(dynamic_ki67[ei])

                    t_values = list(set(t_values))
                    t_values.sort()
                    min_value = t_values[0]
                    max_value = t_values[-1]

                    query_orm = query_orm.extra(
                        where=[f"{column} BETWEEN {min_value} AND {max_value}"]
                    )

                elif column == "sex_cd":
                    t = "','".join(text)
                    query_orm = query_orm.extra(where=[f"{column} IN ('{t}')"])

                else:
                    query_orm = query_orm.extra(
                        where=[f"({column} = '{text}')"])

            else:
                t = "','".join(text)
                query_orm = query_orm.extra(where=[f"{column} IN ('{t}')"])

        elif from_range is not None and to_range is not None:
            if project_id is None:
                if column == "t_category":
                    if viz_filter_type == "static":
                        tmp = ""
                        for e in volcano_static[column]:
                            if from_range in e:
                                row = e.split(",")
                                t = f"' ) OR ({column}='"
                                tmp += t.join(row)
                        query_orm = query_orm.extra(
                            where=[f"({column} = '{tmp}')"])

                    else:
                        query_orm = query_orm.extra(
                            where=[f"({column}= %s OR {column}= %s)"],
                            params=[from_range, to_range],
                        )

                elif column == "n_category":
                    if viz_filter_type == "static":
                        tmp = ""
                        for e in volcano_static[column]:
                            if from_range in e:
                                row = e.split(",")
                                t = f"' ) OR ({column}='"
                                tmp += t.join(row)
                        query_orm = query_orm.extra(
                            where=[f"({column} = '{tmp}')"])
                    else:
                        query_orm = query_orm.extra(
                            where=[f"({column}= %s )"], params=[from_range]
                        )

                elif column == "her2_score":
                    if viz_filter_type == "dynamic":
                        query_orm = query_orm.extra(
                            where=[f"({column}= %s OR {column}= %s)"],
                            params=[from_range, to_range],
                        )
                    else:
                        t = ""
                        qt = "' OR " + column + " = '"
                        t = qt.join(fusion_her2[from_range]) + "'"
                        t = column + " = '" + t
                        query_orm = query_orm.extra(where=[f"{t}"])

                elif column == "ki67_score":
                    if viz_filter_type == "dynamic":
                        query_orm = query_orm.extra(
                            where=[f"({column}= %s OR {column}= %s)"],
                            params=[from_range, to_range],
                        )

                    else:
                        t = column + " BETWEEN " + from_range + " AND " + to_range
                        query_orm = query_orm.extra(where=[f"({t})"])
                else:
                    if viz_filter_type == "dynamic":
                        query_orm = query_orm.extra(
                            where=[f"({column}>= %s AND {column}<= %s)"],
                            params=[from_range, to_range],
                        )

                    else:

                        t = f"{column} >= {from_range} AND {column} <= {to_range}"
                        query_orm = query_orm.extra(where=[f"({t})"])
            else:
                if viz_filter_type == "dynamic":
                    query_orm.extra(
                        where=[f"({column}>= %s AND {column}<= %s)"],
                        params=[from_range, to_range],
                    )
                else:

                    t = f"{column} >= {from_range} AND {column} <= {to_range}"

                    query_orm = query_orm.extra(where=[f"({t})"])
        return query_orm

    def make_venn_json(self, final_response, total_len):
        final_res = dict.copy(final_response)

        if total_len == 1:
            group_str = list(final_res.keys())[0]
            final_res[group_str] = list(set(final_res[group_str]))

        elif total_len >= 2:
            group_keys = list(final_res.keys())

            for i in range(len(group_keys)):
                final_res[group_keys[i]] = list(set(final_res[group_keys[i]]))

            if total_len >=3:
                intersection_all = list(set(final_res[group_keys[0]]) & set(final_res[group_keys[1]]) & set(final_res[group_keys[2]]))
                for e in intersection_all:
                    for key in group_keys:
                        if e in final_res[key]:
                            final_res[key].remove(e)

            for i in range(len(group_keys)):
                for j in range(i + 1, len(group_keys)):
                    intersection_arr = list(set(final_res[group_keys[i]]) & set(final_res[group_keys[j]]))
                    final_res[f"{group_keys[i]}_{group_keys[j]}"] = intersection_arr

                    for e in intersection_arr:
                        final_res[group_keys[i]].remove(e)
                        final_res[group_keys[j]].remove(e)
            if total_len >=3:
                final_res["_".join(group_keys)] = intersection_all

        return final_res

    def clean_fusion_data_using_dict(self, data, rnid_details):
        temp_dict = {}
        gene_dict = {}

        for d in data:
            key = (d["rid"], d["gene"])
            if key not in temp_dict:
                temp_dict[key] = d
                if d["gene"] not in gene_dict:
                    gene_dict[d["gene"]] = {"rid": [d["rid"]], "fid": d["fid"]}
                else:
                    gene_dict[d["gene"]]["rid"].append(d["rid"])

        final_list = []
        for gene in gene_dict:
            rids = gene_dict[gene]["rid"]
            rnids = list(
                set([rnid for rid in rids for rnid in rnid_details.get(rid, [])])
            )
            final_list.append(
                {"rid": rnids, "fid": gene_dict[gene]["fid"], "gene": gene}
            )

        unique_genes = set(d["gene"] for d in final_list)
        return final_list

    def post(self, request):
        try:
            data = request.data
            project_id = data.get("project_id")
            constant_filter_data = filterBoxes
            if project_id is not None:
                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="fusion",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )
            if project_id is not None:
                project_id = project_id.strip()

                available_steps = fetch_user_project_object(project_id)
                available_steps_volcano = available_steps.get("fusion")
                if (
                    not "fusion" in available_steps_volcano
                    and not "clinical_information" in available_steps_volcano
                ):
                    return Response({}, status=status.HTTP_204_NO_CONTENT)
            if serializer.is_valid():
                data = serializer.validated_data

                filter_group = data.get("filterGroup")
                if "group_a" in filter_group:
                    filter_group["group_1"] = filter_group["group_a"]
                    del filter_group["group_a"]
                if "group_b" in filter_group:
                    filter_group["group_2"] = filter_group["group_b"]
                    del filter_group["group_b"]
                if "group_c" in filter_group:
                    filter_group["group_3"] = filter_group["group_c"]
                    del filter_group["group_c"]

                if filter_group and 'index' in filter_group:
                    del filter_group['index']

                main_filter_type = data.get("filterType")

                if filter_group is not None and len(filter_group) > 0:
                    clinical_filters_dict = self.get_group_filter_details(
                        filter_group)
                final_res = {}
                final_result = {}
                new_final_res = {}
                tmp_res = {}
                tmp_sampleid = {}

                if clinical_filters_dict:
                    column = clinical_filters_dict["column"]
                    groups = list(clinical_filters_dict["groups"])
                    filter_type = clinical_filters_dict["type"]
                    groups_list = ["", "1", "2", "3"]

                    queries_orm = {}
                    if project_id is None and filter_type == "boolean":
                        q1_orm = self.orm_generate_query_for_filter(
                            boolean=True,
                            column=column,
                            filter_group=filter_group,
                            viz_filter_type=main_filter_type,
                        )
                        q2_orm = self.orm_generate_query_for_filter(
                            boolean=False,
                            column=column,
                            filter_group=filter_group,
                            viz_filter_type=main_filter_type,
                        )

                        queries_orm["group_1"] = q1_orm
                        queries_orm["group_2"] = q2_orm

                    elif project_id is None and filter_type == "static":
                        if main_filter_type == "static" and filter_type == "static":
                            q1_orm = self.orm_generate_query_for_filter(
                                text="M",
                                column=column,
                                filter_group=filter_group,
                                viz_filter_type=main_filter_type,
                            )
                            q2_orm = self.orm_generate_query_for_filter(
                                text="F",
                                column=column,
                                filter_group=filter_group,
                                viz_filter_type=main_filter_type,
                            )
                            queries_orm["group_1"] = q1_orm
                            queries_orm["group_2"] = q2_orm

                        if main_filter_type == "dynamic":
                            for key, value in filter_group.items():

                                q1_orm = self.orm_generate_query_for_filter(
                                    column=column,
                                    text=value,
                                    filter_group=filter_group,
                                    viz_filter_type=main_filter_type,
                                )
                                queries_orm[key] = q1_orm

                    elif project_id is None:
                        for group in groups:
                            if filter_type == "text":
                                if column == "her2_score":
                                    text = filter_group[str(group)]
                                    q_orm = self.orm_generate_query_for_filter(
                                        column,
                                        text=text,
                                        filter_group=filter_group,
                                        viz_filter_type=main_filter_type,
                                    )
                                    queries_orm.append(q_orm)

                            elif filter_type == "static":
                                if column == "sex_cd":
                                    q1_orm = self.orm_generate_query_for_filter(
                                        text="M",
                                        column=column,
                                        filter_group=filter_group,
                                        viz_filter_type=main_filter_type,
                                    )
                                    q2_orm = self.orm_generate_query_for_filter(
                                        text="F",
                                        column=column,
                                        filter_group=filter_group,
                                        viz_filter_type=main_filter_type,
                                    )
                                    queries_orm.append(q1_orm, q2_orm)
                            else:
                                from_range = filter_group[f"{group}_from"]
                                to_range = filter_group[f"{group}_to"]
                                res_orm = self.orm_generate_query_for_filter(
                                    from_range=from_range,
                                    to_range=to_range,
                                    column=column,
                                    filter_group=filter_group,
                                    viz_filter_type=main_filter_type,
                                )
                                queries_orm["group_" +
                                            groups_list[group]] = res_orm

                    elif project_id is not None:

                        if filter_type == "static":
                            for key, value in filter_group.items():
                                q1_orm = self.orm_generate_query_for_filter(
                                    column=column,
                                    text=value,
                                    filter_group=filter_group,
                                    viz_filter_type=main_filter_type,
                                    project_id=project_id,
                                )
                                queries_orm[key] = q1_orm

                        elif filter_type == "boolean":
                            q1_orm = self.orm_generate_query_for_filter(
                                boolean=True,
                                column=column,
                                filter_group=filter_group,
                                viz_filter_type=main_filter_type,
                                project_id=project_id,
                            )
                            q2_orm = self.orm_generate_query_for_filter(
                                boolean=False,
                                column=column,
                                filter_group=filter_group,
                                viz_filter_type=main_filter_type,
                                project_id=project_id,
                            )

                            queries_orm["group_1"] = q1_orm
                            queries_orm["group_2"] = q2_orm

                        else:
                            for group in groups:
                                from_range = filter_group[f"{group}_from"]
                                to_range = filter_group[f"{group}_to"]
                                res_orm = self.orm_generate_query_for_filter(
                                    from_range=from_range,
                                    to_range=to_range,
                                    column=column,
                                    filter_group=filter_group,
                                    viz_filter_type=main_filter_type,
                                    project_id=project_id,
                                )
                                queries_orm["group_" +
                                            groups_list[group]] = res_orm

                    total_len = 0
                    total_rnids = {}
                    for key, value in queries_orm.items():
                        key = key.replace("_", " ")
                        final_res[key] = []
                        new_final_res[key] = {}
                        rnids = []
                        if project_id is None:
                            query_response = value
                            rnids = [each["id"] for each in query_response]
                        else:
                            query_response = value
                            rnids = [each["id"] for each in query_response]
                        total_rnids[key] = rnids
                        subquery = []
                        rnid_details = {}
                        try:
                            if len(rnids) == 1:
                                subquery = (
                                    RnidDetails.objects.using(settings.DB)
                                    .filter(Q(id=rnids[0]))
                                    .values("id", "brst_key")
                                )
                            elif len(rnids) > 1:
                                subquery = (
                                    RnidDetails.objects.using(settings.DB)
                                    .filter(Q(id__in=rnids))
                                    .values("id", "brst_key")
                                )
                        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError("A database-related error occurred while processing your request.")
                        except Exception as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError("An error occurred while processing your request.")
                        rnid_details = {row["id"]: [row["brst_key"]]
                                        for row in subquery}
                        if len(rnids) >= 1:
                            try:
                                fusion_query = (
                                Fusion.objects.using(settings.DB)
                                .annotate(
                                    gene=Concat(
                                        Concat(
                                            Concat("left_gene_name", Value("||")),
                                            Concat("right_gene_name", Value("||")),
                                            Concat("left_gene_ensmbl_id",
                                                Value("||")),
                                            Concat("left_gene_chr", Value("||")),
                                            Concat("left_hg38_pos", Value("||")),
                                        ),
                                        Concat(
                                            Concat("right_gene_ensmbl_id",
                                                Value("||")),
                                            Concat("right_gene_chr", Value("||")),
                                            Concat("right_hg38_pos", Value("||")),
                                            Concat("junction_read_count",
                                                Value("||")),
                                            Concat("spanning_frag_count",
                                                Value("||")),
                                        ),
                                        Concat("splice_type", Value("||")),
                                        output_field=models.CharField(),
                                    )
                                )
                                .extra(
                                    select={"rid": "rnid.id", "fid": "fusion.id"},
                                    tables=["rnid"],
                                    where=[
                                        "rnid.id = fusion.rnid",
                                        f"fusion.rnid in {tuple(rnids)}",
                                    ]
                                    if len(rnids) > 1
                                    else [
                                        "rnid.id = fusion.rnid",
                                        f"fusion.rnid = {rnids[0]}",
                                    ],
                                )
                                .values("gene", "rid", "fid")
                                .distinct()
                            )
                            except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("A database-related error occurred while processing your request.")
                            except Exception as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("An error occurred while processing your request.")
                            fusion_query = list(fusion_query)
                            fusion_query = self.clean_fusion_data_using_dict(
                                fusion_query, rnid_details
                            )
                        if len(rnids) > 0:

                            for each in fusion_query:
                                final_res[key].append(each["gene"])
                                gene = each["gene"]
                                row = gene.split("||")
                                sample_id = list(each["rid"])
                                if each["gene"] in tmp_sampleid:
                                    tmp_sampleid[each["gene"]].extend(sample_id)
                                else:
                                    tmp_sampleid[each["gene"]] = []
                                    tmp_sampleid[each["gene"]].extend(sample_id)

                                if each["gene"] in new_final_res[key]:
                                    new_final_res[key][each["gene"]].extend(
                                        sample_id)
                                else:
                                    new_final_res[key][each["gene"]] = []
                                    new_final_res[key][each["gene"]].extend(
                                        sample_id)

                                tmp_res[each["gene"]] = {
                                    "id": each["fid"],
                                    "left_gene_name": row[0],
                                    "left_gene_ensmbl_id": row[2],
                                    "left_gene_chr": row[3],
                                    "right_gene_name": row[1],
                                    "right_gene_ensmbl_id": row[5],
                                    "right_gene_chr": row[6],
                                    "left_hg38_pos": row[4],
                                    "right_hg38_pos": row[7],
                                    "junction_read_count": row[8],
                                    "spanning_frag_count": row[9],
                                    "splice_type": row[10],
                                }
                        total_len = total_len + 1
                    vennData = self.make_venn_json(final_res, total_len)
                    final_result["venn"] = vennData
                    final_result["rnids"] = total_rnids
                    final_result["data"] = {}

                    columns = []
                final_result["columns"] = list(set(columns))

                for k, v in vennData.items():
                    final_result["data"][k] = []
                    for e in v:
                        if e in tmp_sampleid:
                            obj1 = dict.copy(tmp_res[e])
                            obj1["sample_id"] = tmp_sampleid[e]
                            final_result["data"][k].append(obj1)
                return Response(final_result, status=status.HTTP_200_OK)
            else:
                return Response({}, status=status.HTTP_204_NO_CONTENT)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            error_message = "An error occurred while processing your request."
            if isinstance(e, IntegrityError):
                error_message = "An integrity error occurred while processing your request."
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError(error_message)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class FusionPlot(APIView):

    def get_output_gtf(self, gene, color, transcript_id):
        try:
            res = []
            transcipts_list = []
            query = f"SELECT * from output_gtf where gene_name='{gene}' and region='exon' and {transcript_id} BETWEEN gtf_start and gtf_end order by rel_end desc"
            output_gtf = Proteome.objects.raw(query)
            if output_gtf is not None:
                i = 0
                for row in output_gtf:
                    transcript = row.transcript_id
                    if transcript not in transcipts_list:
                        transcipts_list.append(transcript)
                    if i == 0:
                        q = f"select * from output_gtf where gene_name ='{gene}' and transcript_id='{transcript}' and region='exon' "
                        exons = Proteome.objects.raw(q)
                        if exons is not None:
                            res = [
                                {
                                    "startCodon": e.gtf_start,
                                    "endCodon": e.gtf_end,
                                    "label": e.transcript_id,
                                    "color": color,
                                }
                                for e in exons
                            ]
                        i = i + 1

            return {"exons": res, "transcripts": transcipts_list}
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        try:
            data = request.data
            fusion_id = data.get("id")
            final_exons = {}
            final_transcripts = {}
            final_pos = {}
            query = f"SELECT 1 as id,left_gene_name,left_gene_chr,left_hg38_pos,right_gene_chr,right_gene_name,right_hg38_pos from fusion where id={fusion_id}"
            fusion_data = Fusion.objects.using(settings.DB).raw(query)

            res = {}
            left_gene_name = ""
            right_gene_name = ""
            if fusion_data is not None:
                for row in fusion_data:
                    left_gene_name = row.left_gene_name
                    right_gene_name = row.right_gene_name
                    final_pos[left_gene_name] = (
                        str(row.left_gene_chr) + ":" + str(row.left_hg38_pos)
                    )
                    final_pos[right_gene_name] = (
                        str(row.right_gene_chr) + ":" + str(row.right_hg38_pos)
                    )

                    res_data = self.get_output_gtf(
                        left_gene_name, "#6f6fff", row.left_hg38_pos
                    )
                    final_exons[left_gene_name] = res_data["exons"]
                    final_transcripts[left_gene_name] = res_data["transcripts"]

                    res_data = self.get_output_gtf(
                        right_gene_name, "#ff4d71", row.right_hg38_pos
                    )
                    final_exons[right_gene_name] = res_data["exons"]
                    final_transcripts[right_gene_name] = res_data["transcripts"]
            res["status"] = True
            if left_gene_name in final_exons and right_gene_name in final_exons:
                if (
                    len(final_exons[left_gene_name]) > 0
                    and len(final_exons[right_gene_name]) > 0
                ):
                    res["exons"] = final_exons
                    res["transcripts"] = final_transcripts
                    res["pos"] = final_pos
                else:
                    res["status"] = False
                    res["msg"] = "No data match found in human genome database"
                    return Response(res, status=status.HTTP_200_OK)

            return Response(res, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class FusionExons(APIView):
    def post(self, request):
        try:
            data = request.data
            transcript_id = data.get("transcript_id")
            gene = data.get("gene")
            type_data = data.get("type")
            color = "#ff4d71"
            if type_data == "left":
                color = "#6f6fff"
            else:
                color = "#ff4d71"

            query = f"select 1 as id,gtf_start,gtf_end,transcript_id from output_gtf where gene_name ='{gene}' and transcript_id='{transcript_id}' and region='exon' "
            output_gtf = Proteome.objects.raw(query)
            if output_gtf is not None:
                i = 0
                res = [
                    {
                        "startCodon": e.gtf_start,
                        "endCodon": e.gtf_end,
                        "label": e.transcript_id,
                        "color": color,
                    }
                    for e in output_gtf
                ]
                return Response(res, status=status.HTTP_200_OK)
            else:
                res = []
                return Response(res, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class HeatMapPlot(APIView):
    def post(self, request):
        try:
            data = request.data
            genes = data["genes"]
            constant_filter_data = filterBoxes
            project_id = data.get("project_id")
            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="heatmap",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )

            if serializer.is_valid() and len(genes) > 0:
                data = serializer.validated_data
                filters = data.get("filter")
                tab_type = data["table_type"]
                cluster = 5
                if "cluster" in data:
                    cluster = data["cluster"]

                heat_type = ""
                if "heat_type" in data:
                    heat_type = data["heat_type"]

                clustering_type = "gene"
                if "clustering_type" in data:
                    clustering_type = data["clustering_type"]

                project_id = data.get("project_id")
                advanse_filters_, advanse_params = "", []
                available_steps_heatmap = None
                if project_id is not None:
                    project_id = project_id.strip()

                    available_steps = fetch_user_project_object(project_id)
                    available_steps_heatmap = available_steps.get("heatmap")
                    if tab_type == "rna" and not "rna" in available_steps_heatmap:
                        return Response(status=204)

                    elif (
                        tab_type == "methylation"
                        and not "methylation" in available_steps_heatmap
                    ):
                        return Response(status=204)

                    elif (
                        tab_type == "proteome" and not "proteome" in available_steps_heatmap
                    ):
                        return Response(status=204)

                    elif tab_type == "phospho" and not "phospho" in available_steps_heatmap:
                        return Response(status=204)

                view_type = data.get("view")

                clinicalFilters = []
                c_query = []
                rnids = []
                if "clinicalFilters" in data:
                    clinicalFilters = data.get("clinicalFilters")
                if len(data["filter"]) or "clinicalFilters" in data:
                    try:
                        c_query = (
                        ClinicalInformation.objects.using(settings.DB)
                        .extra(select={"id": "1", "pt_sbst_no": "pt_sbst_no"})
                        .values("id", "pt_sbst_no")
                        .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                if project_id is not None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_advance_filter_query_formater(
                        data["filter"], False, project_id
                    )
                    if advanse_filters_ != "":
                        c_query = c_query.extra(
                            where=[advanse_filters_], params=advanse_params)
                elif len(data["filter"]):
                    advanse_filters_, advanse_params = orm_filter_query_formater(
                        data["filter"]
                    )
                    if advanse_filters_ != "":
                        c_query = c_query.extra(
                        where=[advanse_filters_], params=advanse_params)

                rnids = [e["pt_sbst_no"] for e in c_query]
                f_ = []
                if clinicalFilters and len(clinicalFilters) > 0:
                    for e in clinicalFilters:
                        f_.append(e)

                cir = ""
                if tab_type == "rna":
                    cir = "rna"
                    select_ = {
                        "id": "1",
                        "gene_name": "gene_name",
                        "gene_vl": view_type,
                        "pt_sbst_no": "rna.pt_sbst_no",
                    }
                    select_.update({x: f"clinical_information.{x}" for x in f_})
                    try:
                        query_orm = (
                        Rna.objects.using(settings.DB)
                        .extra(
                            select=select_,
                        )
                        .values("id", "gene_name", "pt_sbst_no", "gene_vl", *f_)
                        .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                elif tab_type == "methylation":
                    cir = "methylation"
                    select_ = {
                        "id": "1",
                        "gene_name": "gene_name",
                        "site": "target_id",
                        "pt_sbst_no": "methylation.pt_sbst_no",
                        "gene_vl": "gene_vl",
                    }
                    select_.update({x: f"clinical_information.{x}" for x in f_})
                    try:
                        query_orm = (
                        Methylation.objects.using(settings.DB)
                        .extra(
                            select=select_,
                        )
                        .annotate(
                            gene_name_site=Concat(
                                "gene_name", Value("_"), "target_id")
                        )
                        .values(
                            "id", "gene_name_site", "site", "pt_sbst_no", "gene_vl", *f_
                        )
                        .distinct()
                        )

                        site_values = [entry["site"] for entry in query_orm]

                        # Check if all site values are the same
                        if len(set(site_values)) == 1:
                            logger.error('site_values are same')
                            return HttpResponse(status=204)
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")



                elif tab_type == "proteome":
                    cir = "proteome"
                    select_ = {
                        "id": "1",
                        "gene_name": "gene_name",
                        "site": "p_name",
                        "pt_sbst_no": "proteome.pt_sbst_no",
                        "gene_vl": view_type,
                    }
                    select_.update({x: f"clinical_information.{x}" for x in f_})
                    try:
                        query_orm = (
                            Proteome.objects.using(settings.DB)
                            .extra(
                                select=select_,
                            )
                            .values("id", "gene_name", "site", "pt_sbst_no", "gene_vl", *f_)
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                elif tab_type == "phospho":
                    cir = "phospho"
                    select_ = {
                        "id": "1",
                        "gene_name": "gene_name",
                        "site": "site",
                        "pt_sbst_no": "phospho.pt_sbst_no",
                        "gene_vl": view_type,
                    }
                    select_.update({x: f"clinical_information.{x}" for x in f_})
                    try:
                        query_orm = (
                            Phospho.objects.using(settings.DB)
                            .extra(
                                select=select_,
                            )
                            .annotate(gene_name_site=Concat("gene_name", Value("_"), "site"))
                            .values(
                                "id", "gene_name_site", "site", "pt_sbst_no", "gene_vl", *f_
                            )
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")
                    query_orm = query_orm.filter(gene_vl__isnull=False)

                if genes and filters:
                    query_orm = query_orm.extra(
                        tables=["clinical_information"],
                        where=[f"{cir}.pt_sbst_no = clinical_information.pt_sbst_no"],
                    )

                    if len(genes) == 1:
                        query_orm = query_orm.extra(
                            where=[f"{cir}.gene_name = %s"], params=[genes[0]]
                        )
                    else:
                        query_orm = query_orm.extra(
                            where=[f"{cir}.gene_name in {tuple(genes)}"]
                        )

                    if project_id is not None:
                        (
                            advanse_filters_,
                            advanse_params,
                        ) = orm_advance_filter_query_formater(filters, False, project_id)
                    else:
                        advanse_filters_, advanse_params = orm_filter_query_formater(
                            filters
                        )

                    if advanse_filters_:
                        query_orm = query_orm.extra(
                            where=[advanse_filters_], params=advanse_params
                        )
                else:
                    if clinicalFilters and len(clinicalFilters) > 0:
                        query_orm = query_orm.extra(
                            tables=["clinical_information"],
                            where=[
                                f"{cir}.pt_sbst_no = clinical_information.pt_sbst_no"],
                        )
                    if len(genes) == 1:
                        query_orm = query_orm.extra(
                            where=[f"{cir}.gene_name = %s"], params=[genes[0]]
                        )
                    else:
                        query_orm = query_orm.extra(
                            where=[f"{cir}.gene_name in {tuple(genes)}"]
                        )
                    if len(rnids) > 0:
                        if len(rnids) == 1:
                            query_orm = query_orm.extra(
                                where=[f"{cir}.pt_sbst_no = %s"], params=[rnids[0]]
                            )
                        else:
                            query_orm = query_orm.extra(
                                where=[f"{cir}.pt_sbst_no in {tuple(rnids)}"]
                            )

                if tab_type == "methylation":
                    query_orm = query_orm.extra(
                        where=[f"{cir}.target_type = 'T' "])
                else:
                    query_orm = query_orm.extra(
                        where=[f"{cir}.type = 'T' "])

                query_orm = query_orm.order_by(f"{cir}.pt_sbst_no")

                rna_serializer = query_orm

                if rna_serializer:
                    if heat_type == "k-mean":
                        if clustering_type == 'gene':
                            try:
                                df = pd.DataFrame(rna_serializer)

                                if "gene_name_site" in df:
                                    unique_columns = ["gene_name_site", "pt_sbst_no", "gene_vl"]
                                else:
                                    unique_columns = ["gene_name", "pt_sbst_no", "gene_vl"]

                                df = df.drop_duplicates(unique_columns)
                                df["gene_vl"] = df["gene_vl"].fillna(0)
                                df = df.pivot_table(index=unique_columns[0], columns=unique_columns[1], values=unique_columns[2])
                                df = df.fillna(0)
                                df = df.rename_axis(index=unique_columns[0])
                                rnids = df.to_dict().keys()
                                scaler = MinMaxScaler()
                                df_scaled = scaler.fit_transform(df)

                                kmeans = KMeans(
                                    n_clusters=int(cluster),
                                    init="k-means++",
                                    n_init=2,
                                    max_iter=300,
                                    tol=0.0001,
                                    precompute_distances="auto",
                                    verbose=0,
                                    random_state=None,
                                    copy_x=True,
                                    n_jobs=None,
                                    algorithm="full"
                                ).fit(df_scaled)
                                df["labels"] = kmeans.labels_
                                genes = []
                                clusters = [v + 1 for v in df["labels"].to_dict().values()]

                                max_gene_vl = max(entry["gene_vl"] for entry in rna_serializer if isinstance(entry["gene_vl"], float))
                                max_gene_vl_ceil = math.ceil(max_gene_vl / 100) * 100 if max_gene_vl >= 100 else math.ceil(max_gene_vl)

                                min_gene_vl = min(entry["gene_vl"] for entry in rna_serializer if isinstance(entry["gene_vl"], float))
                                min_gene_vl_floor = math.floor(min_gene_vl)
                                temp = {
                                    "data": rna_serializer,
                                    "clusters": clusters,
                                    "max_spectrum_value": max_gene_vl_ceil,
                                    "min_spectrum_value": min_gene_vl_floor
                                }
                                return Response(temp, status=status.HTTP_200_OK)
                            except Exception as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("Error to process this Request")

                        elif clustering_type == 'sample':
                            try:
                                df = pd.DataFrame(rna_serializer)

                                if "gene_name_site" in df.columns:
                                    unique_columns = ["gene_name_site", "pt_sbst_no", "gene_vl"]
                                else:
                                    unique_columns = ["gene_name", "pt_sbst_no", "gene_vl"]
                                df = df.drop_duplicates(unique_columns)


                                df["gene_vl"] = df["gene_vl"].fillna(0)
                                df = df.groupby([unique_columns[0], unique_columns[1]], as_index=False).agg({f"{unique_columns[2]}": "mean"})
                                df = df.pivot(index=unique_columns[1], columns=unique_columns[0], values=unique_columns[2])
                                df = df.fillna(0)
                                df = df.rename_axis(index=unique_columns[0])
                                scaler = MinMaxScaler()
                                df_scaled = scaler.fit_transform(df)

                                kmeans = KMeans(
                                    n_clusters=int(cluster),
                                    init="k-means++",
                                    n_init=2,
                                    max_iter=300,
                                    tol=0.0001,
                                    verbose=0,
                                    random_state=None,
                                    algorithm="full"
                                ).fit(df_scaled)
                                df["labels"] = kmeans.labels_

                                clusters = [v + 1 for v in df["labels"].to_dict().values()]
                                max_gene_vl = max(entry["gene_vl"] for entry in rna_serializer if isinstance(entry["gene_vl"], float))
                                min_gene_vl = min(entry["gene_vl"] for entry in rna_serializer if isinstance(entry["gene_vl"], float))
                                max_gene_vl_ceil = math.ceil(max_gene_vl / 100) * 100 if max_gene_vl >= 100 else math.ceil(max_gene_vl)
                                min_gene_vl_floor = math.floor(min_gene_vl)

                                temp = {
                                    "data": rna_serializer,
                                    "clusters": clusters,
                                    "max_spectrum_value": max_gene_vl_ceil,
                                    "min_spectrum_value": min_gene_vl_floor
                                }

                                return Response(temp, status=status.HTTP_200_OK)

                            except Exception as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("Error to process this Request")

                    else:
                        min_gene_vl = float('inf')
                        max_gene_vl = -float('inf')
                        for entry in rna_serializer:
                            gene_vl = entry["gene_vl"]
                            if isinstance(gene_vl, float):
                                max_gene_vl = max(max_gene_vl, gene_vl)
                                min_gene_vl = min(min_gene_vl, gene_vl)

                        max_gene_vl_ceil = math.ceil(max_gene_vl / 100) * 100 if max_gene_vl >= 100 else math.ceil(max_gene_vl)
                        min_gene_vl_floor = math.floor(min_gene_vl)

                        temp = {
                            "data": rna_serializer,
                            "max_spectrum_value": max_gene_vl_ceil,
                            "min_spectrum_value": min_gene_vl_floor
                        }

                        return Response(temp, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "no data"}, status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class LollipopPlot(APIView):
    def post(self, request):
        try:
            data = request.data
            genes = data["genes"]
            project_id = data.get("project_id")
            constant_filter_data = filterBoxes

            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="lollipop",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )

            if serializer.is_valid() and len(genes) > 0:
                data = serializer.validated_data
                table_type = data["table_type"]
                advanse_filters_ = ""
                advanse_params = []

                if project_id is None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_filter_query_formater(
                        data["filter"]
                    )

                if project_id is not None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_advance_filter_query_formater(
                        data["filter"], False, project_id
                    )

                if len(data["filter"]) and advanse_filters_ == False:
                    return Response(status=204)

                if project_id:
                    available_steps = fetch_user_project_object(project_id)
                    available_steps_lollypop = available_steps.get("lollypop")
                    if table_type == "Mutation":
                        if not "dna_mutation" in available_steps_lollypop:
                            return Response(status=204)
                    elif table_type == "Phospho":
                        if not "phospho" in available_steps_lollypop:
                            return Response(status=204)

                if table_type == "Mutation":
                    try:
                        query_orm = (
                            DnaMutation.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "sample": "tumor_sample_barcode",
                                    "gene": "hugo_symbol",
                                    "protein": "protein_change",
                                    "variant_classification": "variant_classification",
                                    "annotation_transcript": "annotation_transcript",
                                    "refseq_mrna_id": "refseq_mrna_id",
                                }
                            )
                            .values(
                                "sample",
                                "gene",
                                "protein",
                                "variant_classification",
                                "annotation_transcript",
                                "refseq_mrna_id",
                            )
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if advanse_filters_ != "":
                        query_orm = query_orm.extra(
                            tables=["clinical_information"],
                            where=[
                                "dna_mutation.rnid=clinical_information.rnid",
                                advanse_filters_,
                            ],
                            params=advanse_params,
                        )
                    query_orm = query_orm.filter(
                        Q(hugo_symbol=genes)
                        & ~Q(protein_change__isnull=True)
                        & ~Q(protein_change="")
                        & Q(
                            variant_classification__in=dna_mutation_variant_classifications_list
                        )
                    )
                else:
                    try:
                        query_orm = (
                            Phospho.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "sample": "phospho.pt_sbst_no",
                                    "gene": "gene_name",
                                    "site": "site",
                                }
                            )
                            .values("id", "sample", "gene", "site")
                            .distinct()
                        )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                    if advanse_filters_ != "":
                        query_orm = query_orm.extra(
                            tables=["clinical_information"],
                            where=[
                                "phospho.rnid=clinical_information.rnid",
                                advanse_filters_,
                            ],
                            params=advanse_params,
                        )

                    query_orm = query_orm.filter(gene_name=genes)
                try:
                    domains_query_orm = (
                        Interpro.objects.using(settings.DB)
                        .extra(
                            select={
                                "id": "1",
                                "start": "start_codon",
                                "end": "end_codon",
                                "domain": "domain",
                            },
                            tables=["masterphospho"],
                            where=["masterphospho.swiss_prot_acc_id=interpro.protein"],
                        )
                        .values("start", "end", "domain")
                        .distinct()
                    )

                    domains_query_orm = domains_query_orm.extra(
                        where=[
                            f"masterphospho.hugo_symbol = %s ",
                            f"masterphospho.swiss_prot_acc_id is not Null",
                        ],
                        params=[genes],
                    )
                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")
                res = {}
                if len(query_orm) > 0 and len(domains_query_orm) > 0:
                    res["data"] = query_orm
                    res["domains"] = domains_query_orm
                if len(res) == 0:
                    res["data"] = []
                    res["domains"] = []
                    return Response(res, status=204)
                return Response(res, status=200)
            else:
                return Response({"message": "no data"}, status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")

class SurvivalPlot(APIView):
    def __init__(self):
        self.warning_messages = []

    def custom_warning_filter(self, message, category, filename, lineno, file=None, line=None):
        if "A very low variance" in str(message):
            self.warning_messages.append(str(message))

    def get_group_filter_details(self, clinical_filters):
        database_column = clinical_filters.get("column")
        clinical_filters.pop("column", None)
        filter_type = clinical_filters.get("type")
        clinical_filters.pop("type", None)
        filter_keys = list(clinical_filters.keys())
        total_groups = set()

        if filter_type == "static":
            i = 1
            for key in filter_keys:
                total_groups.add(i)
                i = i + 1
        elif filter_type == "number":
            for key in filter_keys:
                total_groups.add(int(key.split("_")[0]))
        # elif filter_type == "text":
        #     if database_column == "her2_score":
        #         for key in filter_keys:
        #             total_groups.add(int(key.split("_")[0]))
            # else:
            #     for key in filter_keys:
            #         total_groups.add(int(key))

        return {"column": database_column, "groups": total_groups, "type": filter_type}

    def survival_rate_calculation(self, rlps_or_death_drtn_list):
        rlps_or_death_drtn = sorted(
            rlps_or_death_drtn_list, key=lambda d: d["duration"]
        )
        total_elements = len(rlps_or_death_drtn)
        counter = 1
        final = []
        exist = False
        for i in rlps_or_death_drtn:
            if i["duration"] <= 0:
                exist = True
                final.append({"x": 0, "y": 100, "sample": i["rn_key"]})
                continue
            percentage = 100 - (counter / total_elements) * 100
            percentage_ceil = float("%.2f" % percentage)
            final.append(
                {"x": i["duration"], "y": percentage_ceil,
                    "sample": i["rn_key"]}
            )
            counter += 1

        if exist == False:
            final.insert(0, {"x": 0, "y": 100, "sample": ""})
        return final

    def relapse_duration_none_or_not(self, rlps_or_death_cnfr_drtn_or_value, ybc_key):
        if rlps_or_death_cnfr_drtn_or_value is not None:
            rlps_or_death = rlps_or_death_cnfr_drtn_or_value
        else:
            rlps_or_death = 0
        return {"duration": rlps_or_death, "rn_key": ybc_key}

    def run_kaplan_meier_model(self,query,is_mutation=None,project_db=False,filter_label=None,survival_type=None):
        if project_db == False and len(query) > 0 and "smok_yn" in query[0]:
            rnid_set.clear()
        query_response = query
        rlps_cnfr_or_death_drtn = []
        samples_count = 0
        mutations = [
            "In_Frame_Ins",
            "Frame_Shift_Del",
            "Frame_Shift_Ins",
            "Missense_Mutation",
            "Nonsense_Mutation",
            "Splice_Site",
            "In_Frame_Del",
            "Germline",
        ]
        coxData = []

        if len(query_response) > 0:
            for val in query_response:
                pt_sbst_no = val["pt_sbst_no"]
                survive = 0

                if survival_type == "recurrence" and val["rlps_yn"] == "Y":
                    survive = 1
                if survival_type == "survival" and val["death_yn"] == "Y":
                    survive = 1

                cox_object = {
                    "var1": random.randint(0, 255),
                    "var2": random.randint(0, 255),
                    "duration": val["rlps_cnfr_drtn"]
                    if survival_type == "recurrence"
                    else val["death_cnfr_drtn"],
                    "survival": survive,
                }

                coxData.append(cox_object)

                value_ = (
                    val["rlps_cnfr_drtn"]
                    if survival_type == "recurrence"
                    else val["death_cnfr_drtn"]
                )
                if is_mutation is None:
                    if pt_sbst_no in rnid_set:
                        continue
                    else:
                        rnid_set.add(pt_sbst_no)
                if is_mutation is not None:
                    if not is_mutation:
                        if val["variant_classification"] not in mutations:
                            if pt_sbst_no in rnid_set:
                                continue
                            else:
                                rnid_set.add(pt_sbst_no)
                            samples_count += 1
                            rlps_or_death = self.relapse_duration_none_or_not(
                                value_, val["ybc_key"]
                            )
                            rlps_cnfr_or_death_drtn.append(rlps_or_death)
                            continue
                    else:
                        if val["variant_classification"] in mutations:
                            if pt_sbst_no in rnid_set:
                                continue
                            else:
                                rnid_set.add(pt_sbst_no)
                            samples_count += 1
                            rlps_or_death = self.relapse_duration_none_or_not(
                                value_, val["ybc_key"]
                            )
                            rlps_cnfr_or_death_drtn.append(rlps_or_death)
                            continue
                else:

                    if project_db == False and "smok_yn" in query:
                        smoking = ""
                        if val["smok_yn"] == True:
                            if val["smok_curr_yn"] == False:
                                smoking = "TRUE"
                        elif val["smok_yn"] == False:
                            smoking = "FALSE"
                        if val["smok_curr_yn"]:
                            smoking = "TRUE"
                        filter_label = filter_label.strip()

                        rlps_or_death = self.relapse_duration_none_or_not(
                            value_, val["ybc_key"]
                        )
                        rlps_cnfr_or_death_drtn.append(rlps_or_death)
                        samples_count += 1

                    else:
                        rlps_or_death = self.relapse_duration_none_or_not(
                            value_, val["ybc_key"]
                        )
                        rlps_cnfr_or_death_drtn.append(rlps_or_death)
                        samples_count += 1

        if samples_count > 0:
            duration = [1 if i["duration"] >
                        0 else 0 for i in rlps_cnfr_or_death_drtn]
            km_model = KaplanMeierModel()
            rlps_cnfr_drtn_float = [i["duration"]
                                    for i in rlps_cnfr_or_death_drtn]
            km_model.fit(rlps_cnfr_drtn_float, duration, alpha=0.95)
            pandas_df = km_model.get_survival_table()
            x_axis_time = list(pandas_df["Time"])
            y_axis_risk = [math.ceil(i * 100)
                           for i in list(pandas_df["Survival"])]
            final = self.survival_rate_calculation(rlps_cnfr_or_death_drtn)
            return {
                "time": x_axis_time,
                "risk": y_axis_risk,
                "samples_count": samples_count,
                "final": final,
            }

        return {"time": [], "risk": [], "samples_count": samples_count, "final": []}

    def orm_generate_query_for_filter(
        self,
        table,
        column=None,
        gene_name=None,
        boolean=None,
        text=None,
        from_range=None,
        to_range=None,
        is_clinical=None,
        viz_filter_type=None,
        project_id=None,
        survival_type=None,
    ):
        gene_column_name = "gene_name"
        if table == "dna_mutation" and project_id is None:
            gene_column_name = "hugo_symbol"
        if survival_type == "recurrence":
            select_ = {
                "id": "1",
                "pt_sbst_no": "pt_sbst_no",
                "rlps_cnfr_drtn": "rlps_cnfr_drtn",
                "rlps_yn": "rlps_yn",
                "ybc_key": "rnid.brst_key",
            }
            values_ = select_.keys()
        else:
            select_ = {
                "id": "1",
                "pt_sbst_no": "pt_sbst_no",
                "death_cnfr_drtn": "death_cnfr_drtn",
                "death_yn": "death_yn",
                "ybc_key": "rnid.brst_key",
            }
            values_ = select_.keys()
        query_orm = (
            ClinicalInformation.objects.using(settings.DB)
            .extra(
                select=select_,
                tables=["rnid"],
                where=["clinical_information.rnid=rnid.id"],
            )
            .values(*values_)
        )

        if is_clinical is None:
            query_orm = query_orm.extra(
                where=[f"clinical_information.rnid={table}.rnid"]
            )

        if boolean is not None:
            if project_id is None:
                boo_str = "Y" if boolean == True else "N"
                if boolean == True:
                    query_orm = query_orm.extra(where=[f"({column} = 'Y')"])
                else:
                    query_orm = query_orm.extra(where=[f"({column} != 'Y')"])
            else:
                boo_str = 1 if boolean == True else 0
                query_orm = query_orm.extra(
                    where=[f"({column} = %s)"], params=[str(boo_str)]
                )

        elif text is not None:
            if project_id is None:
                if column == "smok_yn":
                    value = text[0].split("||")[1]
                    col = text[0].split("||")[0]
                    query_orm = query_orm.extra(where=[f"({col} = '{value}')"])
                elif column == "t_category" or column == "n_category":
                    t = "','".join(text)
                    query_orm = query_orm.extra(where=[f"{column} IN ('{t}')"])

                # elif column == "her2_score":
                #     t_values = []
                #     for ei in text:
                #         t_values.extend(dynamic_her2[ei])
                #     t_values = list(set(t_values))
                #     t_values_str = "','".join(str(n) for n in t_values)
                #     query_orm = query_orm.extra(
                #         where=[f"{column} IN ('{t_values_str}')"])

                # elif column == "ki67_score":
                #     t_values = []
                #     for ei in text:
                #         t_values.extend(dynamic_ki67[ei])
                #     t_values = list(set(t_values))
                #     t_values_str = "','".join(str(n) for n in t_values)
                #     query_orm = query_orm.extra(
                #         where=[f"{column} IN ('{t_values_str}')"])

                elif column == "sex_cd":
                    t = "','".join(text)
                    query_orm = query_orm.extra(where=[f"{column} IN ('{t}')"])
                elif column == "stage":
                    t = "','".join(text)
                    query_orm = query_orm.extra(where=[f"{column} IN ('{t}')"])

                else:
                    query_orm = query_orm.extra(
                        where=[f"({column} = '{text}')"])

            else:
                t = "','".join(text)
                query_orm = query_orm.extra(where=[f"{column} IN ('{t}')"])

        elif from_range is not None and to_range is not None:
            if project_id is None:
                if column == "t_category":
                    if viz_filter_type == "static":
                        tmp = ""
                        for e in volcano_static[column]:
                            if from_range in e:
                                row = e.split(",")
                                t = f"' ) OR ({column}='"
                                tmp += t.join(row)
                        query_orm = query_orm.extra(
                            where=[f"({column} = '{tmp}')"])

                    else:
                        query_orm = query_orm.extra(
                            where=[f"({column}= %s OR {column}= %s)"],
                            params=[from_range, to_range],
                        )

                elif column == "n_category":
                    if viz_filter_type == "static":
                        tmp = ""
                        for e in volcano_static[column]:
                            if from_range in e:
                                row = e.split(",")
                                t = f"' ) OR ({column}='"
                                tmp += t.join(row)
                        query_orm = query_orm.extra(
                            where=[f"({column} = '{tmp}')"])
                    else:
                        query_orm = query_orm.extra(
                            where=[f"({column}= %s )"], params=[from_range]
                        )
                # elif column == "her2_score":
                #     if viz_filter_type == "dynamic":
                #         query_orm = query_orm.extra(
                #             where=[f"({column}= %s OR {column}= %s)"],
                #             params=[from_range, to_range],
                #         )
                #     else:
                #         t = ""
                #         qt = "' OR " + column + " = '"
                #         t = qt.join(dynamic_her2[from_range]) + "'"
                #         t = column + " = '" + t
                #         query_orm = query_orm.extra(where=[f"{t}"])

                # elif column == "ki67_score":
                #     if viz_filter_type == "dynamic":
                #         query_orm = query_orm.extra(
                #             where=[f"({column}= %s OR {column}= %s)"],
                #             params=[from_range, to_range],
                #         )

                #     else:
                #         t = ""
                #         t = " AND ".join(str(n)
                #                          for n in dynamic_ki67[from_range])
                #         t = column + " BETWEEN " + t
                #         query_orm = query_orm.extra(where=[f"{t}"])

                else:

                    query_orm = query_orm.extra(
                        where=[f"({column}>= %s AND {column}<= %s)"],
                        params=[from_range, to_range],
                    )
            else:
                query_orm = query_orm.extra(
                    where=[f"({column}>= %s AND {column}<= %s)"],
                    params=[from_range, to_range],
                )

        if (gene_name is not None) and (is_clinical is None):
            query_orm = query_orm.extra(
                where=[f" AND {table}.{gene_column_name}='{gene_name}'"]
            )
        if survival_type == "recurrence":
            query_orm = query_orm.filter(rlps_yn__isnull=False)
        else:
            query_orm = query_orm.filter(death_yn__isnull=False)
        return query_orm

    def run_query_and_generate_graph_data(
        self, query_list, project_db=False, survival_type=None
    ):
        x_axis_survival_time_set = set()
        y_axis_data = set()
        kaplan_results_list = []
        headers = ["Time"]
        sample_counts_per_query = {}
        pvalue = None
        final_line_chart = {}
        for index, query_string in enumerate(query_list):
            filter_label = query_string["label"]
            headers.append(filter_label)
            is_mutation = query_string.get("mutation")
            if is_mutation is not None:
                kaplan_algorithm_data = self.run_kaplan_meier_model(
                    query_string["query"],
                    is_mutation=is_mutation,
                    project_db=project_db,
                    filter_label=filter_label,
                    survival_type=survival_type,
                )
            else:
                kaplan_algorithm_data = self.run_kaplan_meier_model(
                    query_string["query"],
                    project_db=project_db,
                    filter_label=filter_label,
                    survival_type=survival_type,
                )


            final_line_chart[filter_label] = kaplan_algorithm_data["final"]
            sample_counts_per_query[filter_label] = kaplan_algorithm_data[
                "samples_count"
            ]
            for set_data in set(kaplan_algorithm_data["time"]):
                x_axis_survival_time_set.add(set_data)
            for set_data in set(kaplan_algorithm_data["risk"]):
                y_axis_data.add(set_data)
            kaplan_dict = {}
            for sub_index, time_value in enumerate(kaplan_algorithm_data["time"]):
                kaplan_dict[
                    kaplan_algorithm_data["time"][sub_index]
                ] = kaplan_algorithm_data["risk"][sub_index]
            kaplan_results_list.append(kaplan_dict)

        x_axis_survival_time_list = list(x_axis_survival_time_set)
        x_axis_survival_time_list.sort(reverse=True)
        kaplan_matrix = [[i] for i in x_axis_survival_time_list]
        tool_tip_list = [[] for _ in kaplan_matrix]
        E = []
        T = []
        G = []
        group_index = 1
        for single_result_dict in kaplan_results_list:
            for k, v in single_result_dict.items():
                E.append(k)
                G.append(group_index)
                if k <= 0:
                    T.append(0)
                else:
                    T.append(1)
            group_index = group_index + 1
            single_result_dict_values_list = list(single_result_dict.values())
            last_value = (
                min(single_result_dict_values_list)
                if len(single_result_dict_values_list) > 0
                else 0
            )
            for row_index, row_data in enumerate(kaplan_matrix):
                x_axis_key = row_data[0]
                y_axis_point = single_result_dict.get(x_axis_key)
                if y_axis_point is None:
                    tool_tip_list[row_index].append(0)
                    y_axis_point = last_value
                else:
                    tool_tip_list[row_index].append(1)
                last_value = y_axis_point
                kaplan_matrix[row_index].append(y_axis_point)
        y_axis_data_list = list(y_axis_data)
        y_axis_data_list.sort()
        x_axis_survival_time_list.sort()
        x_axis_size = len(x_axis_survival_time_list)
        y_axis_size = len(y_axis_data_list)
        common_points = min(x_axis_size, y_axis_size)

        x_time_arr = np.array(x_axis_survival_time_list)
        y_axis_datalist = np.array(y_axis_data_list)

        try:
            if group_index == 2:
                p_value = 0
            else:
                try:
                    result = multivariate_logrank_test(E, G, T)
                    p_value = list(result.summary["p"])[0]
                    if math.isnan(p_value):
                        p_value = 0
                except:
                    p_value = 0
            r_value = 0

        except:
            p_value, r_value = 0, 0
        return {
            "final": final_line_chart,
            "all": [headers] + kaplan_matrix,
            "sample_counts": sample_counts_per_query,
            "pvalue": p_value,
            "rvalue": r_value,
        }

    def get(self, request):
        final = {}
        data = request.data
        filter_gene = "TP53"
        project_id = data.get("project_id")
        filter_query = ""
        query = "select distinct 1 as id, pt_sbst_no, rlps_cnfr_drtn, rlps_yn, diag_age, sex_cd from clinical_information"
        if filter_gene != "" and filter_gene is not None:
            filter_query = f"{query} join dna_mutation on dna_mutation.tumor_sample_barcode=clinical_information.pt_sbst_no where dna_mutation.hugo_symbol='{filter_gene}' "
        normal_query_response = ClinicalInformation.objects.raw(query)
        rlps_cnfr_drtn = []
        for val in normal_query_response:
            if val.rlps_cnfr_drtn is not None:
                rlps_cnfr_drtn.append(val.rlps_cnfr_drtn)
                continue
            rlps_cnfr_drtn.append(0)
        duration = [1 if i > 0 else 0 for i in rlps_cnfr_drtn]
        km_model = KaplanMeierModel()
        km_model.fit(rlps_cnfr_drtn, duration, alpha=0.95)
        pandas_df = km_model.get_survival_table()
        final["normal"] = {
            "time": list(pandas_df["Time"]),
            "risk": list(pandas_df["Number at risk"]),
        }
        if filter_query != "":
            if project_id is not None:
                project_id = project_id.strip()

                available_steps = fetch_user_project_object(project_id)
                available_steps_survival = available_steps.get("survival")
                if "advance" in available_steps_survival:
                    query_filters_object = ClinicalInformation.objects.using(
                        settings.DB
                    ).raw(filter_query)
            else:
                query_filters_object = []
            if query_filters_object:
                rlps_cnfr_drtn_filter = []
                for val in query_filters_object:
                    if val.rlps_cnfr_drtn is not None:
                        rlps_cnfr_drtn_filter.append(val.rlps_cnfr_drtn)
                        continue
                    rlps_cnfr_drtn_filter.append(0)
                duration_filter = [
                    1 if i > 0 else 0 for i in rlps_cnfr_drtn_filter]
                km_model = KaplanMeierModel()
                km_model.fit(rlps_cnfr_drtn_filter,
                             duration_filter, alpha=0.95)
                pandas_df_filter = km_model.get_survival_table()
                final[filter_gene] = {
                    "time": list(pandas_df_filter["Time"]),
                    "risk": list(pandas_df_filter["Number at risk"]),
                }

        return Response(final, status=status.HTTP_200_OK)

    def run_cox_regression(self, cox_filter, project_id=None):

        query = (
            ClinicalInformation.objects.using(settings.DB)
            .distinct()
            .values("id", "pt_sbst_no")
        )

        d = []
        get_keys = []

        for k in cox_filter:
            if cox_filter[k] == True:
                get_keys.append(k)

        for ci_row in query:
            pt_sbst_no = ci_row["pt_sbst_no"]
            query = (
                "select distinct 1 as id,* from clinical_information where pt_sbst_no='"
                + pt_sbst_no
                + "'"
            )

            for e in ClinicalInformation.objects.using(settings.DB).raw(query):
                if project_id is None:
                    d.append(
                        {
                            "BodyMassIndex": e.bmi_vl if e.bmi_vl else 0,
                            "AlcoholConsumption": 1 if e.drnk_yn else 0,
                            "DiabetesHistory": 1 if e.diabetes_yn else 0,
                            "HypertensionHistory": 1 if e.hyp_yn else 0,
                            # "Stage": e.stage if e.stage else 0,
                            # "FamilyHistoryofBreastCancer": 1 if e.fmhs_brst_yn else 0,
                            # "IntakeOfContraceptivePill": 1 if e.oc_yn else 0,
                            # "HormoneReplaceTherapy": 1 if e.hrt_yn else 0,
                            # "Menopause": 1 if e.meno_yn else 0,
                            # "Childbirth": 1 if e.delv_yn else 0,
                            # "DiagnosisofBilateralBreastCancer": 1
                            # if e.bila_cncr_yn
                            # else 0,
                            # "FirstMenstrualAge": e.mena_age
                            # if e.mena_age is not None
                            # else 0,
                            # "ERTestResults": e.er_score
                            # if e.er_score is not None
                            # else 0,
                            # "PRTestResults": e.pr_score
                            # if e.pr_score is not None
                            # else 0,
                            # "Ki67Index": e.ki67_score
                            # if e.ki67_score is not None
                            # else 0,
                            "AgeOfDiagnosis": e.diag_age
                            if e.diag_age is not None
                            else 0,
                            "rlps_yn": 1 if e.rlps_yn else 0,
                            "rlps_cnfr_drtn": e.rlps_cnfr_drtn
                            if e.rlps_cnfr_drtn is not None
                            else 0,
                        }
                    )
                else:
                    project_id = project_id.strip()

                    row = e.__dict__
                    row_obj = {}
                    for key in cox_filter:
                        row_obj[key] = row[key] if row[key] is not None else 0
                        row_obj["rlps_yn"] = 1 if e.rlps_yn else 0
                        row_obj["rlps_cnfr_drtn"] = (
                            e.rlps_cnfr_drtn if e.rlps_cnfr_drtn is not None else 0
                        )
                    d.append(row_obj)

        selectColumns = ["rlps_yn", "rlps_cnfr_drtn"]
        for k, v in cox_filter.items():
            if v:
                selectColumns.append(k)
        df = pd.DataFrame(d)
        dx = df[selectColumns]
        dx = dx.dropna()
        res = {}
        survival_plot = SurvivalPlot()
        warnings.filterwarnings("always", category=UserWarning)
        warnings.showwarning = survival_plot.custom_warning_filter

        try:
            cph = get_cox_object()
            tmpColumns = [
                e for e in selectColumns if (e != "rlps_yn" and e != "rlps_cnfr_drtn")
            ]
            formula = " + ".join(tmpColumns)
            cph.fit(dx, duration_col="rlps_cnfr_drtn",
                    event_col="rlps_yn", formula=formula)
            summary = cph.summary
            columns = summary.columns.tolist()
            data = summary.to_json()
            num_of_observation = len(cph.event_observed)
            num_of_event_observ = len([e for e in cph.event_observed if e])

            # Failing sometimes and stopping the server
            my_stringIObytes = BytesIO()
            plot = cph.plot()
            plot.margins(0.15)
            fig = plot.figure
            fig.tight_layout()
            fig.savefig(my_stringIObytes, format="png")
            my_stringIObytes.seek(0)
            my_base64_pngData = base64.b64encode(my_stringIObytes.read())
            plot.remove()

            likelihood = cph.log_likelihood_ratio_test()
            likelihoodData = (
                str(likelihood.test_statistic)
                + " on "
                + str(likelihood.degrees_freedom)
                + " df"
            )
            selectColumns.remove("rlps_yn")
            selectColumns.remove("rlps_cnfr_drtn")
            dx.iloc[0:0]
            res = {
                "columns": columns,
                "data": data,
                "clinical_filter": selectColumns,
                "duration_col": cph.duration_col,
                "event_col": cph.event_col,
                "baseline_estimation_method": cph.baseline_estimation_method,
                "num_of_observation": num_of_observation,
                "num_of_event_observ": num_of_event_observ,
                "log_likelihood_": cph.log_likelihood_,
                "concordance_index_": cph.concordance_index_,
                "log_likelihood_ratio_test": likelihoodData,
                "AIC_partial_": cph.AIC_partial_,
                "image": my_base64_pngData,
            }
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
        finally:
            captured_warnings = survival_plot.warning_messages
            if len(captured_warnings) > 0:
                pattern = r'Column (\S+)'
                matches = re.search(pattern, captured_warnings[0])
                if matches:
                    error_message = f'Column {matches.group(1)} have very low variance. A very low variance means that the column {matches.group(1)} completely determines whether a subject dies or not.'
                    res = {"errorMessage": error_message}
                else:
                    res = {"errorMessage": captured_warnings[0]}
                survival_plot = None

        return res

    def post(self, request):
        try:
            rnid_set.clear()
            data = request.data
            constant_filter_data = filterBoxes
            project_id = data.get("project_id")

            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="survival",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )
            if serializer.is_valid():
                data = serializer.validated_data
                survival_type = data.get("survival_type")
                viz_filter_type = data.get("filterType")
                filter_gene = data.get("filter_gene")
                gene_table_name = data.get("gene_database")
                clinical_filters = data.get("group_filters")
                clinical_filters_dict = {}
                available_steps_survival = {}
                is_clinical = data.get("clinical")
                cox_filter = data.get("coxFilter")

                if clinical_filters and 'index' in clinical_filters:
                    del clinical_filters['index']

                if project_id is not None:
                    available_steps = fetch_user_project_object(project_id)
                    available_steps_survival = available_steps.get("survival")
                    if "clinical_information" not in available_steps_survival:
                        return Response({}, status=status.HTTP_204_NO_CONTENT)

                if survival_type == "cox":
                    res = {}
                    if project_id is not None:
                        res = self.run_cox_regression(
                            cox_filter, project_id=project_id
                        )
                    else:
                        res = self.run_cox_regression(cox_filter)

                    if res:
                        return Response(res, status=status.HTTP_200_OK)
                    else:
                        return Response(res, status=status.HTTP_204_NO_CONTENT)
                else:
                    try:
                        global_select = {
                            "id": "1",
                            "pt_sbst_no": "pt_sbst_no",
                            "ybc_key": "rnid.brst_key",
                        }
                        rlps_or_death_dict = {}
                        if survival_type == "recurrence":
                            rlps_or_death_dict["rlps_cnfr_drtn"] = "rlps_cnfr_drtn"
                            rlps_or_death_dict["rlps_yn"] = "rlps_yn"

                        elif survival_type == "survival":
                            rlps_or_death_dict["death_cnfr_drtn"] = "death_cnfr_drtn"
                            rlps_or_death_dict["death_yn"] = "death_yn"

                        global_select.update(rlps_or_death_dict)

                        values_ = global_select.keys()
                        try:
                            query = (
                                ClinicalInformation.objects.using(settings.DB)
                                .extra(
                                    select=global_select,
                                    tables=["rnid"],
                                    where=["clinical_information.rnid=rnid.id"],
                                )
                                .values(*values_)
                                .distinct()
                            )
                        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError("A database-related error occurred while processing your request.")
                        except Exception as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError("An error occurred while processing your request.")
                        all_queries = [{"query": query, "label": "All"}]

                        if clinical_filters is not None and len(clinical_filters) > 0:
                            clinical_filters_dict = self.get_group_filter_details(
                                clinical_filters
                            )

                        if clinical_filters_dict:
                            column = clinical_filters_dict["column"]
                            if project_id is None and column != "smok_yn":
                                column_label = filter_choices_column_names[column]
                            elif project_id is None:
                                column_label = ""
                            elif project_id is not None:
                                column_label = column

                            filter_type = clinical_filters_dict["type"]
                            all_queries = []
                            if filter_type == "boolean":
                                q1 = self.orm_generate_query_for_filter(
                                    gene_table_name,
                                    column,
                                    boolean=True,
                                    gene_name=filter_gene,
                                    is_clinical=is_clinical,
                                    viz_filter_type=viz_filter_type,
                                    project_id=project_id,
                                    survival_type=survival_type,
                                )
                                q2 = self.orm_generate_query_for_filter(
                                    gene_table_name,
                                    column,
                                    boolean=False,
                                    gene_name=filter_gene,
                                    is_clinical=is_clinical,
                                    viz_filter_type=viz_filter_type,
                                    project_id=project_id,
                                    survival_type=survival_type,
                                )
                                all_queries = [
                                    {"query": q1, "label": f"{column_label} TRUE"},
                                    {"query": q2, "label": f"{column_label} FALSE"},
                                ]
                            elif filter_type == "static":
                                if column == "sex_cd":
                                    q1 = self.orm_generate_query_for_filter(
                                        gene_table_name,
                                        column,
                                        text="M",
                                        gene_name=filter_gene,
                                        is_clinical=is_clinical,
                                        project_id=project_id,
                                        survival_type=survival_type,
                                    )
                                    q2 = self.orm_generate_query_for_filter(
                                        gene_table_name,
                                        column,
                                        text="F",
                                        gene_name=filter_gene,
                                        is_clinical=is_clinical,
                                        project_id=project_id,
                                        survival_type=survival_type,
                                    )
                                    all_queries = [
                                        {"query": q1, "label": f"{column_label} Male"},
                                        {"query": q2, "label": f"{column_label} Female"},
                                    ]
                                else:
                                    if viz_filter_type == "dynamic":
                                        for key, value in clinical_filters.items():
                                            q1 = self.orm_generate_query_for_filter(
                                                gene_table_name,
                                                column,
                                                text=value,
                                                gene_name=filter_gene,
                                                is_clinical=is_clinical,
                                                project_id=project_id,
                                                survival_type=survival_type,
                                            )

                                            group_name = "-".join(value)
                                            all_queries.append(
                                                {"query": q1, "label": f"{group_name}"}
                                            )

                            else:

                                if project_id is None and column == "smok_yn":
                                    select_ = {
                                        "id": "1",
                                        "pt_sbst_no": "pt_sbst_no",
                                        "ybc_key": "rnid.brst_key",
                                        "smok_yn": "smok_yn",
                                    }
                                    select_.update(rlps_or_death_dict)

                                    values_ = global_select.keys()
                                    try:
                                        query_orm = (
                                        ClinicalInformation.objects.using(
                                            settings.DB)
                                        .extra(
                                            select=select_,
                                            tables=["rnid"],
                                            where=[
                                                "clinical_information.rnid=rnid.id"],
                                        )
                                        .values(*values_)
                                        .distinct()
                                        )
                                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                        add_line_in_logger_file()
                                        logger.exception(e)
                                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                                    except Exception as e:
                                        add_line_in_logger_file()
                                        logger.exception(e)
                                        return HttpResponseServerError("An error occurred while processing your request.")
                                    select_ = {
                                        k: v
                                        for k, v in select_.items()
                                        if k not in rlps_or_death_dict
                                    }
                                    all_queries.append(
                                        {"query": query_orm, "label": f"No Smoking"}
                                    )
                                    all_queries.append(
                                        {"query": query_orm, "label": f"Current Smoking"}
                                    )
                                    all_queries.append(
                                        {"query": query_orm, "label": f"Past Smoking"}
                                    )
                                elif project_id is None and column == "stage":
                                    select_ = {
                                        "id": "1",
                                        "pt_sbst_no": "pt_sbst_no",
                                        "ybc_key": "rnid.brst_key",
                                        "stage": "stage",
                                    }
                                    select_.update(rlps_or_death_dict)

                                    values_ = global_select.keys()
                                    try:
                                        query_orm = (
                                        ClinicalInformation.objects.using(
                                            settings.DB)
                                        .extra(
                                            select=select_,
                                            tables=["rnid"],
                                            where=[
                                                "clinical_information.rnid=rnid.id"],
                                        )
                                        .values(*values_)
                                        .distinct()
                                        )
                                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                        add_line_in_logger_file()
                                        logger.exception(e)
                                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                                    except Exception as e:
                                        add_line_in_logger_file()
                                        logger.exception(e)
                                        return HttpResponseServerError("An error occurred while processing your request.")
                                    select_ = {
                                        k: v
                                        for k, v in select_.items()
                                        if k not in rlps_or_death_dict
                                    }
                                    all_queries.append(
                                        {"query": query_orm, "label": f"Stage_I"}
                                    )
                                    all_queries.append(
                                        {"query": query_orm, "label": f"Stage_II"}
                                    )
                                    all_queries.append(
                                        {"query": query_orm, "label": f"Stage_III"}
                                    )
                                    all_queries.append(
                                        {"query": query_orm, "label": f"Stage_IV"}
                                    )
                                else:
                                    for group in clinical_filters_dict["groups"]:
                                        if project_id is None and filter_type == "text":
                                            if column == "her2_score":
                                                from_range = clinical_filters[
                                                    f"{group}_from"
                                                ]
                                                to_range = clinical_filters[f"{group}_to"]
                                                q = self.orm_generate_query_for_filter(
                                                    gene_table_name,
                                                    column,
                                                    from_range=from_range,
                                                    to_range=to_range,
                                                    gene_name=filter_gene,
                                                    is_clinical=is_clinical,
                                                    viz_filter_type=viz_filter_type,
                                                    survival_type=survival_type,
                                                )
                                            else:
                                                text = clinical_filters[str(group)]
                                                q = self.orm_generate_query_for_filter(
                                                    gene_table_name,
                                                    column,
                                                    text=text,
                                                    gene_name=filter_gene,
                                                    is_clinical=is_clinical,
                                                    viz_filter_type=viz_filter_type,
                                                    survival_type=survival_type,
                                                )

                                        else:
                                            from_range = clinical_filters[f"{group}_from"]
                                            to_range = clinical_filters[f"{group}_to"]
                                            q = self.orm_generate_query_for_filter(
                                                gene_table_name,
                                                column,
                                                from_range=from_range,
                                                to_range=to_range,
                                                gene_name=filter_gene,
                                                is_clinical=is_clinical,
                                                viz_filter_type=viz_filter_type,
                                                project_id=project_id,
                                                survival_type=survival_type,
                                            )

                                        if project_id is None and column in (
                                            "t_category",
                                            "n_category",
                                        ):
                                            all_queries.append(
                                                {"query": q, "label": f"{to_range}"}
                                            )
                                        else:
                                            all_queries.append(
                                                {
                                                    "query": q,
                                                    "label": f"{from_range}~{to_range}",
                                                }
                                            )

                        if not clinical_filters_dict and not is_clinical:
                            gene_column_name = "gene_name"
                            if gene_table_name == "dna_mutation":
                                gene_column_name = "hugo_symbol"
                                if (not "dna_mutation" in available_steps_survival) and (
                                    project_id is not None
                                ):
                                    return Response(status=204)
                                select_ = {
                                    "id": "1",
                                    "pt_sbst_no": "clinical_information.pt_sbst_no",
                                    "ybc_key": "rnid.brst_key",
                                    "variant_classification": "dna_mutation.variant_classification",
                                }
                                select_.update(rlps_or_death_dict)
                                values_ = select_.keys()
                                try:
                                    queryset = (
                                        ClinicalInformation.objects.using(settings.DB)
                                        .select_related("rnid")
                                        .extra(
                                            select=select_,
                                            tables=["rnid", "dna_mutation"],
                                            where=[
                                                "clinical_information.rnid = rnid.id",
                                            ],
                                        )
                                        .values(*values_)
                                    )
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")
                                select_ = {
                                    k: v
                                    for k, v in select_.items()
                                    if k not in rlps_or_death_dict
                                }

                                if project_id is None:
                                    queryset = queryset.extra(
                                        where=[" clinical_information.rlps_yn='Y' "]
                                    )
                                elif project_id:
                                    queryset = queryset.extra(
                                        where=[" clinical_information.rlps_yn= 1 "]
                                    )

                                queryset_mutation = queryset.extra(
                                    where=[
                                        "clinical_information.rnid = dna_mutation.rnid",
                                        "dna_mutation.tumor_sample_barcode is not NULL",
                                        f"{gene_table_name}.{gene_column_name}='{filter_gene}'",
                                    ]
                                )

                                queryset_no_mutation = queryset.extra(
                                    where=[
                                        f"clinical_information.rnid NOT IN (SELECT dna_mutation.rnid FROM dna_mutation WHERE {gene_table_name}.{gene_column_name}='{filter_gene}')",
                                        "dna_mutation.tumor_sample_barcode is not NULL",
                                    ]
                                )

                                all_queries = [
                                     {
                                        "query": queryset_no_mutation,
                                        "label": "No Mutation",
                                        "mutation": False,
                                    }
                                ]
                                all_queries.append(
                                    {
                                        "query": queryset_mutation,
                                        "label": "Mutation",
                                        "mutation": True,
                                    }
                                )

                            if gene_table_name == "rna":
                                select_ = {
                                    "id": "1",
                                    "pt_sbst_no": "clinical_information.pt_sbst_no",
                                    "ybc_key": "rnid.brst_key",
                                }
                                select_.update(rlps_or_death_dict)
                                values_ = select_.keys()

                                if (not "rna" in available_steps_survival) and (
                                    project_id is not None
                                ):
                                    return Response(status=204)
                                try:
                                    up_regulation_query_up = (
                                        ClinicalInformation.objects.using(settings.DB)
                                        .select_related("rnid")
                                        .extra(
                                            select=select_,
                                            tables=["rnid", "rna"],
                                            where=[
                                                "clinical_information.rnid = rnid.id",
                                                "clinical_information.rnid = rna.rnid",
                                            ],
                                        )
                                        .values(*values_)
                                    )
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")

                                up_regulation_query_up = up_regulation_query_up.extra(
                                    where=[
                                        " rna.z_score >= 1 ",
                                        f"{gene_table_name}.{gene_column_name}='{filter_gene}'",
                                    ]
                                )

                                if project_id is None:
                                    up_regulation_query_up = up_regulation_query_up.extra(
                                        where=["clinical_information.rlps_yn='Y'"]
                                    )
                                else:
                                    up_regulation_query_up = up_regulation_query_up.extra(
                                        where=["clinical_information.rlps_yn='1'"]
                                    )
                                try:
                                    down_regulation_query_down = (
                                        ClinicalInformation.objects.using(settings.DB)
                                        .select_related("rnid")
                                        .extra(
                                            select=select_,
                                            tables=["rnid", "rna"],
                                            where=[
                                                "clinical_information.rnid = rnid.id",
                                                "clinical_information.rnid = rna.rnid",
                                            ],
                                        )
                                        .values(*values_)
                                    )
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")

                                down_regulation_query_down = down_regulation_query_down.extra(
                                    where=[
                                        " rna.z_score <= -1 ",
                                        f"{gene_table_name}.{gene_column_name}='{filter_gene}'",
                                    ]
                                )

                                if project_id is None:
                                    down_regulation_query_down = (
                                        down_regulation_query_down.extra(
                                            where=[
                                                "clinical_information.rlps_yn='Y'"]
                                        )
                                    )
                                else:
                                    down_regulation_query_down = (
                                        down_regulation_query_down.extra(
                                            where=[
                                                "clinical_information.rlps_yn='1'"]
                                        )
                                    )

                                all_queries = [
                                    {
                                        "query": up_regulation_query_up,
                                        "label": f"RNA UP regulation",
                                    }
                                ]
                                all_queries.append(
                                    {
                                        "query": down_regulation_query_down,
                                        "label": f"RNA Down Regulation",
                                    }
                                )

                            if gene_table_name == "proteome":
                                if (not "proteome" in available_steps_survival) and (
                                    project_id is not None
                                ):
                                    return Response(status=204)
                                select_ = {
                                    "id": "1",
                                    "pt_sbst_no": "clinical_information.pt_sbst_no",
                                    "ybc_key": "rnid.brst_key",
                                }
                                select_.update(rlps_or_death_dict)

                                values_ = select_.keys()
                                try:
                                    up_regulation_query_up = (
                                        ClinicalInformation.objects.using(settings.DB)
                                        .select_related("rnid")
                                        .extra(
                                            select=select_,
                                            tables=["rnid", "proteome"],
                                            where=[
                                                "clinical_information.rnid = rnid.id",
                                                "clinical_information.rnid = proteome.rnid",
                                                "proteome.type = 'T' "
                                            ],
                                        )
                                        .values(*values_)
                                    )

                                    up_regulation_query_up = up_regulation_query_up.extra(
                                        where=[
                                            " proteome.z_score > 1.5 ",
                                            f"{gene_table_name}.{gene_column_name}='{filter_gene}'",
                                        ]
                                    )

                                    if project_id is None:
                                        up_regulation_query_up = up_regulation_query_up.extra(
                                            where=[" clinical_information.rlps_yn='Y' "]
                                        )
                                    else:
                                        up_regulation_query_up = up_regulation_query_up.extra(
                                            where=[" clinical_information.rlps_yn='1' "]
                                        )
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")

                                try:
                                    down_regulation_query_down = (
                                        ClinicalInformation.objects.using(settings.DB)
                                        .select_related("rnid")
                                        .extra(
                                            select=select_,
                                            tables=["rnid", "proteome"],
                                            where=[
                                                "clinical_information.rnid = rnid.id",
                                                "clinical_information.rnid = proteome.rnid",
                                                "proteome.type = 'T' "
                                            ],
                                        )
                                        .values(*values_)
                                    )

                                    down_regulation_query_down = down_regulation_query_down.extra(
                                        where=[
                                            " proteome.z_score < 0.5 ",
                                            f"{gene_table_name}.{gene_column_name}='{filter_gene}'",
                                        ]
                                    )

                                    if project_id is None:
                                        down_regulation_query_down = (
                                            down_regulation_query_down.extra(
                                                where=[
                                                    " clinical_information.rlps_yn='Y' "]
                                            )
                                        )
                                    else:
                                        down_regulation_query_down = (
                                            down_regulation_query_down.extra(
                                                where=[
                                                    " clinical_information.rlps_yn='1' "]
                                            )
                                        )
                                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")

                                all_queries = [
                                    {
                                        "query": up_regulation_query_up,
                                        "label": f"Proteome UP regulation",
                                    }
                                ]
                                all_queries.append(
                                    {
                                        "query": down_regulation_query_down,
                                        "label": f"Proteome Down Regulation",
                                    }
                                )

                        if len(available_steps_survival) > 0:
                            data = self.run_query_and_generate_graph_data(
                                all_queries, project_db=True, survival_type=survival_type
                            )
                        else:
                            data = self.run_query_and_generate_graph_data(
                                all_queries, survival_type=survival_type
                            )

                        if all_queries[0]["label"] == "All":
                            try:
                                count_query_true = "select 1 as id, count(distinct pt_sbst_no) as count from clinical_information where rlps_yn='Y'"
                                count_query_false = "select 1 as id, count(distinct pt_sbst_no) as count from clinical_information where not rlps_yn='Y'"
                                if project_id is not None:
                                    count_true_object = ClinicalInformation.objects.using(
                                        settings.DB
                                    ).raw(count_query_true)
                                    count_false_object = ClinicalInformation.objects.using(
                                        settings.DB
                                    ).raw(count_query_false)
                                else:
                                    count_true_object = ClinicalInformation.objects.using(
                                        settings.DB
                                    ).raw(count_query_true)
                                    count_false_object = ClinicalInformation.objects.using(
                                        settings.DB
                                    ).raw(count_query_false)
                            except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                            except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return HttpResponseServerError("An error occurred while processing your request.")

                            data["sample_counts"] = {
                                "Cancer Recurred": count_true_object[0].count,
                                "Cancer Not Recurred": count_false_object[0].count,
                            }
                        if data:
                            add_line_in_logger_file()
                            return Response(data, status=status.HTTP_200_OK)
                        else:
                            return Response({"message": "no data"}, status=204)
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return Response(
                            {"message": "Error to process the request"}, status=400
                        )
            else:
                return Response({"message": "no data"}, status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class ScatterPlot(APIView):
    def best_fit_slope_and_intercept(self, xs, ys):
        m = (((mean(xs) * mean(ys))) - mean(xs * ys)) / (
            ((mean(xs) * mean(xs)) - mean(xs * xs))
        )
        b = mean(ys) - m * mean(xs)
        return m, b

    def post(self, request):
        try:
            data = request.data
            genes = data["genes"]
            project_id = data.get("project_id")

            constant_filter_data = filterBoxes

            if project_id is not None:
                project_id = project_id.strip()

                available_steps = fetch_user_project_object(project_id)
                available_steps_scatter = available_steps.get("scatter")
                if (
                    not "proteome" in available_steps_scatter
                    or not "rna" in available_steps_scatter
                ):
                    return Response(status=204)

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="scatter",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )

            if serializer.is_valid() and len(genes) > 0:

                data = serializer.validated_data
                genes = data["genes"]
                g_ = genes
                if len(genes) > 1 and len(genes) != 0:
                    genes = str(tuple(genes))
                else:
                    genes = f"('{genes[0]}')"

                advanse_filters_ = ""
                advanse_params = []

                if project_id is None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_filter_query_formater(
                        data["filter"]
                    )

                if project_id is not None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_advance_filter_query_formater(
                        data["filter"], False, project_id
                    )
                try:
                    query_orm = (
                        Proteome.objects.using(settings.DB)
                        .extra(
                            tables=["rna", "proteome"],
                            where=["proteome.pt_sbst_no = rna.pt_sbst_no"],
                            select={
                                "id": "1",
                                "gene": "rna.gene_name",
                                "pt_sbst_no": "proteome.pt_sbst_no",
                                "x": "rna.z_score",
                                "y": "proteome.z_score",
                            },
                        )
                        .values("id", "gene", "pt_sbst_no", "x", "y")
                    )

                    if advanse_filters_ != "":
                        query_orm = query_orm.extra(
                            tables=["clinical_information"],
                            where=[
                                "rna.pt_sbst_no = clinical_information.pt_sbst_no",
                                advanse_filters_,
                            ],
                            params=advanse_params,
                        )

                    query_orm = query_orm.extra(
                        where=[
                            f"rna.gene_name in {genes} and proteome.type = 'T'",
                            f"proteome.gene_name in {genes} ",
                            f"(proteome.z_score IS NOT NULL) and (rna.z_score is not NULL)",
                        ]
                    )
                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")
                scatter_data = query_orm
                final = {}
                xs1 = []
                ys1 = []
                for m in scatter_data:
                    gene_name = m["gene"]
                    if gene_name not in final:
                        final[gene_name] = []
                        final[gene_name].append(
                            {"x": m["x"], "y": m["y"], "sample": m["pt_sbst_no"]}
                        )
                    else:
                        final[gene_name].append(
                            {"x": m["x"], "y": m["y"], "sample": m["pt_sbst_no"]}
                        )
                    xs1.append(m["x"])
                    ys1.append(m["y"])

                datasets = [
                    {
                        "label": j,
                        "backgroundColor": "#%02X%02X%02X" % (color(), color(), color()),
                        "data": n,
                    }
                    for j, n in final.items()
                ]

                r_value = ""
                p_value = ""

                xs = np.array(xs1, dtype=np.float64)
                ys = np.array(ys1, dtype=np.float64)
                if len(g_) == 1:
                    if len(xs) > 0 and len(ys) > 0:
                        m, b = self.best_fit_slope_and_intercept(xs, ys)
                        regression_line = [[x, (m * x) + b] for x in xs]
                        slope, intercept, r_value, p_value, std_err = stats.linregress(
                            xs, ys
                        )
                        datasets.append(
                            {
                                "label": "line datasets",
                                "fill": False,
                                "data": regression_line,
                                "type": "line",
                            }
                        )
                else:
                    try:
                        slope, intercept, r_value, p_value, std_err = stats.linregress(
                            xs, ys
                        )
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("Error to process this Request")

                content = {"datasets": datasets, "r_value": format_number_roundup(
                    r_value), "p_value": format_number_roundup(p_value)}

                return Response(content, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class PcaPlot(APIView):

    def post(self, request):
        try:
            data = request.data
            project_id = data.get("project_id")
            genes = data["genes"]
            tab_type = data["table_type"]

            constant_filter_data = filterBoxes

            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="pca",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )

            if serializer.is_valid():
                data = serializer.validated_data


                if len(genes) > 1 and len(genes) != 0:
                    genes = tuple(genes)

                advanse_filters_ = ""
                advanse_params = []

                if project_id is None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_filter_query_formater(
                        data["filter"]
                    )

                if project_id is not None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_advance_filter_query_formater(
                        data["filter"], False, project_id
                    )

                try:
                    if tab_type == "proteome":
                        query_orm = (
                            Proteome.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "gene_name": "gene_name",
                                    "pt_sbst_no": "pt_sbst_no",
                                    "gene_vl": "gene_vl",
                                    "group": "type"
                                },
                            )
                            .values("gene_name", "pt_sbst_no", "gene_vl", "group")
                        )
                    elif tab_type == "rna":
                        query_orm = (
                            Rna.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "gene_name": "gene_name",
                                    "pt_sbst_no": "pt_sbst_no",
                                    "gene_vl": "gene_vl",
                                    "group": "type"
                                },
                            )
                            .values("gene_name", "pt_sbst_no", "gene_vl", "group")
                        )

                    if genes != ["all-genes"]:
                    # Apply the gene filter in both cases, rna and proteome, if "all genes" not selected
                        if len(genes) > 0:
                            query_orm = query_orm.filter(gene_name__in=genes)

                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as o:
                    add_line_in_logger_file()
                    logger.exception(o)
                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")

                df = pd.DataFrame.from_records(query_orm)
                matrix = df.pivot_table(index=['pt_sbst_no', 'group'], columns='gene_name', values='gene_vl', aggfunc='first')

                sample_list = matrix.index.get_level_values(0)
                group = matrix.index.get_level_values(1)
                # matrix.reset_index(drop=True, inplace=True)
                # matrix = matrix.dropna(axis=1)  # Drop columns with empty values
                matrix = matrix.fillna(0) # Fills NaNs with 0
                n_samples, n_features = matrix.shape
                if n_samples < 2 or n_features < 2:
                    return Response({"error": "Not enough samples or features to perform PCA"}, status=status.HTTP_400_BAD_REQUEST)

                pca = PCA(n_components=2)
                pca_matrix = pca.fit_transform(matrix)
                ratio = pca.explained_variance_ratio_
                pca_columns = ['pca_component_1', 'pca_component_2']
                pca_df = pd.DataFrame(pca_matrix, columns=pca_columns)
                pca_df['pt_sbst_no'] = sample_list
                pca_df['group'] = group

                pca_dict = {
                    pca['pt_sbst_no'] if pca['pt_sbst_no'].endswith(('_N', '_T')) else f"{pca['pt_sbst_no']}_{pca['group']}": pca
                    for pca in pca_df.to_dict('records')
                }

                final = {}
                xs1 = []
                ys1 = []
                for m in pca_dict.values():
                    group = m["group"]
                    if group not in final:
                        final[group] = []
                    final[group].append(
                        {"x": m["pca_component_1"], "y": m["pca_component_2"], "sample": m["pt_sbst_no"]}
                    )
                    xs1.append(m["pca_component_1"])
                    ys1.append(m["pca_component_2"])

                datasets = [
                    {
                        "label": group,
                        "backgroundColor": "#EA594B" if group == "T" else "#2EA562",
                        "data": data_points,
                    }
                    for group, data_points in final.items()
                ]

                content = {"datasets": datasets, "ratio": ratio.tolist()}
                return Response(content, status=status.HTTP_200_OK)

        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class IgvViewPlot(APIView):
    def post(self, request):
        try:
            data = request.data
            genes = data["genes"]
            project_id = data.get("project_id") ######
            # logger.error(f'settings db = {settings.DB}')

            constant_filter_data = filterBoxes
            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="cnv",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )

            if serializer.is_valid() and len(genes) > 0:
                data = serializer.validated_data
                advanse_filters_ = ""
                advanse_params = []
                if len(data["filter"]):
                    advanse_filters_, advanse_params = orm_filter_query_formater(
                        data["filter"]
                    )
                if project_id is not None:
                    available_steps = fetch_user_project_object(project_id)
                    available_steps_igv = available_steps.get("igv")

                    if len(data["filter"]):
                        (
                            advanse_filters_,
                            advanse_params,
                        ) = orm_advance_filter_query_formater(
                            data["filter"], False, project_id
                        )
                    if not "cnv" in available_steps_igv:
                        return Response(status=204)
                try:
                    query_orm = (
                        Cnv.objects.using(settings.DB).extra(
                            select={
                                "id": "1",
                                "gene": "cnv.gene",
                                "chr": "cnv.chromosome",
                                "start": "cnv.start_pos",
                                "end": "cnv.end_pos",
                                "Num_probes": "cnv.probes",
                                "value": "cnv.cn",
                                "sample": "cnv.pt_sbst_no" if project_id else "rnid.brst_key",
                            },
                            tables=[] if project_id else ["rnid"],
                            where=[] if project_id else ["rnid.id=cnv.r_fk_id"],
                        )
                    ).values(
                        "id", "gene", "chr", "start", "end", "Num_probes", "value", "sample"
                    )

                    if project_id is None and advanse_filters_ != "":
                        query_orm = query_orm.extra(
                            tables=["clinical_information"],
                            where=["cnv.r_fk_id=clinical_information.rnid"],
                        )

                    if project_id is not None and advanse_filters_ != "":
                        query_orm = query_orm.extra(
                            tables=["clinical_information"],
                            where=["cnv.rnid=clinical_information.rnid"],
                        )
                except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("A database-related error occurred while processing your request.")
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")

                if len(genes) == 1:
                    query_orm = query_orm.filter(Q(gene=genes[0]))
                else:
                    query_orm = query_orm.filter(Q(gene__in=genes))

                if advanse_filters_ != "":
                    query_orm = query_orm.extra(
                        where=[advanse_filters_], params=advanse_params
                    )

                for k in query_orm:
                    k["chr"] = k["chr"].replace("chr", "")

                if query_orm:
                    return Response(query_orm, status=200)
                else:
                    return Response({"message": "no data"}, status=204)
            else:
                return Response({"message": "no data"}, status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class BoxPlot(APIView):
    def post(self, request):
        try:
            data = request.data
            project_id = data.get("project_id")
            constant_filter_data = filterBoxes

            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="boxplot",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )
            if serializer.is_valid():
                data = serializer.validated_data
                genes_orm = data["genes"]
                view_type = data.get("view")
                tab_type = data["table_type"]
                available_steps_box = None
                gene_sepal_value = {}
                if project_id is not None:
                    available_steps = fetch_user_project_object(project_id)
                    available_steps_box = available_steps.get("box")
                    if tab_type == "proteome" and "proteome" not in available_steps_box:
                        return Response(status=204)
                    elif tab_type == "rna" and "rna" not in available_steps_box:
                        return Response(status=204)
                advanse_filters_ = ""
                advanse_params = []

                if project_id is None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_filter_query_formater(
                        data["filter"]
                    )
                if project_id is not None and len(data["filter"]):
                    advanse_filters_, advanse_params = orm_advance_filter_query_formater(
                        data["filter"], False, project_id
                    )

                content = {}
                if tab_type == "proteome":
                    try:
                        query_orm = (
                            Proteome.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "pt_sbst_no": "proteome.pt_sbst_no",
                                    "gene": "gene_name",
                                    "y": "gene_vl" if view_type == "gene_vl" else "z_score",
                                    "type": "type",
                                }
                            )
                            .values("id", "pt_sbst_no", "gene", "y", "type", "gene_vl", "z_score")
                        )
                        if advanse_filters_ != "":
                            query_orm = query_orm.extra(
                                tables=["clinical_information"],
                                where=["proteome.rnid = clinical_information.rnid"],
                            )

                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                elif tab_type == "rna":
                    try:
                        query_orm = (
                            Rna.objects.using(settings.DB)
                            .extra(
                                select={
                                    "id": "1",
                                    "pt_sbst_no": "rna.pt_sbst_no",
                                    "gene": "gene_name",
                                    "y": "gene_vl" if view_type == "gene_vl" else "z_score",
                                    "type": "type",
                                }
                            )
                            .values("id", "pt_sbst_no", "gene", "y", "type", "gene_vl", "z_score")
                        )
                        if advanse_filters_ != "":
                            query_orm = query_orm.extra(
                                tables=["clinical_information"],
                                where=["rna.rnid = clinical_information.rnid"],
                            )
                    except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("A database-related error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")


                query_orm = query_orm.filter(gene_name__in=genes_orm)

                if advanse_filters_ != "":
                    query_orm = query_orm.extra(
                        where=[advanse_filters_], params=advanse_params
                    )

                if view_type == "gene_vl":
                    query_orm = query_orm.filter(
                        Q(gene_vl__isnull=False) | Q(gene_vl__gt=1)
                    )
                elif view_type == "z_score":
                    query_orm = query_orm.filter(
                        Q(z_score__isnull=False) | Q(z_score__gt=1)
                    )

                scatter_data = list(query_orm)
                r = [
                    {
                        "Sepal_Length": m["y"],
                        "Species": m["gene"],
                        "Sample": m["pt_sbst_no"],
                        "type": m["type"],
                    }
                    for m in scatter_data
                ]

                gene_sepal_value = {m["gene"]: [] for m in scatter_data}
                for m in scatter_data:
                    gene_sepal_value[m["gene"]].append(m["y"])

                p_value = {}

                gene_data_dict = {item['gene']: [] for item in scatter_data}

                for item in scatter_data:
                    gene_data_dict[item['gene']].append(item)

                for key, value in gene_data_dict.items():
                    df = pd.DataFrame(value)

                    df.replace([np.inf, -np.inf], np.nan, inplace=True)
                    df.dropna(subset=['y', 'gene_vl'], inplace=True)

                    # n_df, t_df = df[df['type'] == 'N'].reset_index(drop=True), df[df['type'] == 'T'].reset_index(drop=True)

                    n_df = df[df['type'] == 'N'].reset_index(drop=True)
                    t_df = df[df['type'] == 'T'].reset_index(drop=True)

                    if not n_df.empty and not t_df.empty:
                        # Homogeneity of variances X
                        bartlett_pvalue = bartlett(t_df['y'], n_df['y']).pvalue

                        if bartlett_pvalue < 0.05:
                            # Homogeneity of variances is not assumed
                            res1 = ttest_ind(t_df['gene_vl'], n_df['gene_vl'], equal_var=False)
                        else:
                            # Homogeneity of variances is assumed
                            res1 = ttest_ind(t_df['gene_vl'], n_df['gene_vl'])

                        # Check for null or infinite p-value
                        if res1.pvalue is not None and not np.isnan(res1.pvalue) and res1.pvalue != np.inf and res1.pvalue != -np.inf:
                            p_value[key] = format_number_roundup(res1.pvalue)
                        else:
                            # Handle null or infinite p-value
                            p_value[key] = None
                    else:
                        # Handle the case when one of the DataFrames is empty
                        p_value[key] = None


                if r:
                    content["datasets"] = r
                    content["p_value"] = p_value

                if len(content) == 0:
                    return Response(status=204)

                return Response(content, status=status.HTTP_200_OK)
            else:
                return Response({}, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class VolcanoPlot(APIView):
    def deseq_calculations(self, group_a_rnid, group_b_rnid, genes, deseq_csv_file_path, viz_type, log2fc, pval):
        log2fc= float(log2fc)
        pval= float(pval)
        file_name = (str(datetime.now())
                     .replace("-", "_")
                     .replace(":", "_")
                     .replace(" ", "_")
                     .replace(".", "_")
        )
        try:
            if deseq_csv_file_path is None:
                if viz_type == "proteome":
                    df = pd.read_csv(
                        os.path.join(
                            settings.BASE_DIR,
                            "static/db_files/example_vol_proteome.csv",
                        ),
                        converters={i: int_converter for i in all_proteome_cols},
                    )
                else:
                    df = pd.read_csv(
                        os.path.join(
                            settings.BASE_DIR,
                            "static/db_files/example_vol_transcriptome.csv",
                        ),
                        converters={i: int_converter for i in all_integer_cols},
                    )
            else:
                df = pd.read_csv(
                    deseq_csv_file_path,
                    converters={i: int_converter for i in all_integer_cols}
                )
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

        df = df.fillna(0)
        df = df[["id"] + group_a_rnid + group_b_rnid]


        sample_count_a = len(group_a_rnid)
        sample_count_b = len(group_b_rnid)
        input_file_name = f"media/{file_name}_input"
        input_file_path = os.path.join(settings.BASE_DIR, input_file_name)
        group_file_name = f"media/{file_name}_group"
        group_file_path = os.path.join(settings.BASE_DIR, group_file_name)
        output_file_name = f"media/{file_name}_output"
        output_file_path = os.path.join(settings.BASE_DIR, output_file_name)

        with open(group_file_path, "w") as group_file_open:
            writer = csv.writer(group_file_open, delimiter="\t")
            writer.writerow(["Sample_ID", "Condition"])
            for ctrl_rnid in group_a_rnid:
                writer.writerow([ctrl_rnid, "Control"])
            for ctrl_rnid in group_b_rnid:
                writer.writerow([ctrl_rnid, "Treated"])

        df.to_csv(input_file_path, index=False)

        command = f"Rscript static/DEG_limma.R {input_file_path} {output_file_path} {group_file_path} {sample_count_a} {sample_count_b}"

        os.system(command)
        part_a = []
        part_b = []
        for index, i in enumerate(group_a_rnid):
            part_a.append(f"A_{index+1}")
        for index, i in enumerate(group_b_rnid):
            part_b.append(f"B_{index+1}")
        table_data = []
        sample_counts = {"1": sample_count_a, "2": sample_count_b}
        response_list = [
            {"data": [], "backgroundColor": "black", "label": "Selected Genes"},
            {"data": [], "backgroundColor": "blue", "label": "Log2 FC"},
            {"data": [], "backgroundColor": "red", "label": "p-value"},
            {"data": [], "backgroundColor": "gray", "label": "NS"},
        ]
        d3_response = []

        if not os.path.exists(output_file_path):
            try:
                os.remove(input_file_path)
                os.remove(group_file_path)
                # os.remove(output_file_path)
            except Exception as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("Error to process this Request")
            return None
        with open(output_file_path) as outfile:
            reader = csv.reader(outfile)
            for index, row in enumerate(reader):
                if index == 0:
                    continue
                gene = row[0]
                log_2_fold_change = row[1]
                p_value = row[4]
                fdr = row[5]

                log_2_fold_change = (
                    0 if log_2_fold_change == "" else float(log_2_fold_change)
                )

                p_value_original = p_value

                p_value_original = (
                    float(p_value_original) if p_value_original is not None else 0
                )

                fdr_original = fdr

                fdr_original = (
                    float(fdr_original) if fdr_original is not None else 0
                )

                if log_2_fold_change != 0:
                    log_2_fold_change = float(
                        "{:.2f}".format(log_2_fold_change))

                p_value = 0 if p_value == "" else float(p_value)

                if "e" in str(p_value):
                    formatted_p_value = "%.4e" % p_value
                    p_value = float(formatted_p_value)

                elif p_value != 0:
                    p_value = format_number_roundup(p_value)

                fdr = 0 if fdr == "" else float(fdr)

                if "e" in str(fdr):
                    formatted_fdr = "%.4e" % fdr
                    fdr = float(formatted_fdr)

                elif fdr != 0:
                    fdr = format_number_roundup(fdr)

                table_data.append(
                    {
                        "gene": gene,
                        "p_value": p_value,
                        "log2(fold_change)": log_2_fold_change,
                        "fdr": fdr,
                    }
                )

                if gene in genes:
                    d3_dict["show"] = True
                d3_dict = {}
                if log_2_fold_change <= -log2fc and p_value <= pval:
                    d3_dict = {
                        "gene": gene,
                        "p_value": abs(math.log10(p_value_original)),
                        "fdr": abs(math.log10(fdr_original)),
                        "log2(fold_change)": log_2_fold_change,
                        "color": "blue",
                        "original_p_value": p_value,
                        "original_fdr": fdr
                    }
                    response_list[1]["data"].append(
                        {"x": log_2_fold_change, "y": p_value, "gene": gene}
                    )
                elif log_2_fold_change >= log2fc and p_value <= pval:
                    d3_dict = {
                        "gene": gene,
                        "p_value": abs(math.log10(p_value_original)),
                        "fdr": abs(math.log10(fdr_original)),
                        "log2(fold_change)": log_2_fold_change,
                        "color": "red",
                        "original_p_value": p_value,
                        "original_fdr": fdr
                    }
                    response_list[2]["data"].append(
                        {"x": log_2_fold_change, "y": p_value, "gene": gene}
                    )
                elif gene in genes:
                    d3_dict = {
                        "gene": gene,
                        "p_value": abs(math.log10(p_value_original)),
                        "fdr": abs(math.log10(fdr_original)),
                        "log2(fold_change)": log_2_fold_change,
                        "color": "black",
                        "original_p_value": p_value,
                        "original_fdr": fdr
                    }
                    response_list[0]["data"].append(
                        {"x": log_2_fold_change, "y": p_value, "gene": gene}
                    )
                else:
                    d3_dict = {
                        "gene": gene,
                        "p_value": abs(math.log10(p_value_original)),
                        "fdr": abs(math.log10(fdr_original)),
                        "log2(fold_change)": log_2_fold_change,
                        "color": "grey",
                        "original_p_value": p_value,
                        "original_fdr": fdr
                    }
                    response_list[3]["data"].append(
                        {"x": log_2_fold_change, "y": p_value, "gene": gene}
                    )
                d3_response.append(d3_dict)
        try:
            os.remove(input_file_path)
            os.remove(group_file_path)
            os.remove(output_file_path)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("Error to process this Request")

        table_data = [
            item
            for item in table_data
            if item["p_value"] <= pval
            and (item["log2(fold_change)"] >= log2fc or item["log2(fold_change)"] <= -log2fc)
        ]

        return {
            "table_data": table_data,
            "samples": sample_counts,
            "d3_response": d3_response,
        }

    def post(self, request):
        try:
            username = request.user.username
            data = request.data
            project_id = data.get("project_id")
            log2fc = 1.5
            pval = 0.05
            if data.get("log2fc"):
                log2fc = data.get("log2fc")
            if data.get("pval"):
                pval = data.get("pval")


            constant_filter_data = filterBoxes

            if project_id is not None:
                project_id = project_id.strip()

                d = KeysAndValuesFilterJson(request=request._request)
                filter_json = d.post(request)
                constant_filter_data = filter_json.data

            serializer = MyPayloadSerializer(
                data=request.data,
                viz="volcano",
                context={"request": request,
                        "constant_filter_data": constant_filter_data},
            )
            if project_id is not None:
                available_steps = fetch_user_project_object(project_id)
                available_steps_volcano = available_steps.get("volcano")
                if (
                    not "rna" in available_steps_volcano
                    and not "clinical_information" in available_steps_volcano
                ):
                    return Response(status=204)

            genes = data["genes"]
            if serializer.is_valid() and len(genes) > 0:
                data = serializer.validated_data
                filter_group = data.get("filterGroup")

                if filter_group and 'index' in filter_group:
                    del filter_group['index']

                volcanoProteomeType = data.get("volcanoProteomeType")
                volcanoTranscriptomeType = "N"
                if data.get("volcanoTranscriptomeType"):
                    volcanoTranscriptomeType = data.get("volcanoTranscriptomeType")
                main_filter_type = data.get("filterType")
                if volcanoProteomeType is not None:
                    viz_type = "proteome"
                elif volcanoProteomeType is None and volcanoTranscriptomeType is not None:
                    viz_type = "transcriptome"

                response_list = []
                group_a_rnid_orm = set()
                group_b_rnid_orm = set()
                group_a_query_orm = []
                group_b_query_orm = []
                # try:
                if filter_group is not None and len(filter_group) > 0:

                    filter_column = filter_group.get("column")
                    filter_type = filter_group.get("type")

                    if project_id is None:
                        try:
                            base_query_orm = (
                                ClinicalInformation.objects.extra(
                                    select={
                                        "id": "1",
                                        "pt_sbst_no": "clinical_information.pt_sbst_no",
                                    },
                                    tables=(
                                        ["proteomevolcano"]
                                        if volcanoProteomeType is not None
                                        else ["transcriptomevolcano"]
                                        if volcanoTranscriptomeType is not None
                                        else ["volcano"]
                                    ),
                                    where=(
                                        [
                                            "clinical_information.pt_sbst_no=proteomevolcano.pt_sbst_no"
                                            ]
                                        if volcanoProteomeType is not None
                                        else ["clinical_information.pt_sbst_no=transcriptomevolcano.pt_sbst_no"]
                                        if volcanoTranscriptomeType is not None
                                        else ["clinical_information.pt_sbst_no=volcano.pt_sbst_no"]
                                    ),
                                )
                                .values("id", "pt_sbst_no")
                                .distinct()
                            )
                        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                            error_message = "A database-related error occurred while processing your request."
                            if isinstance(e, IntegrityError):
                                error_message = "An integrity error occurred while processing your request."
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError(error_message)
                        except Exception as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError("An error occurred while processing your request.")
                    else:
                        try:
                            base_query_orm = (
                                ClinicalInformation.objects.using(settings.DB)
                                .extra(
                                    select={
                                        "id": "1",
                                        "pt_sbst_no": "clinical_information.pt_sbst_no",
                                    },
                                    tables=["proteomevolcano"]
                                    if volcanoProteomeType is not None
                                    else ["transcriptomevolcano"]
                                    if volcanoTranscriptomeType is not None
                                    else ["rna"],
                                    where=[
                                        "clinical_information.pt_sbst_no=proteomevolcano.pt_sbst_no"
                                    ]
                                    if volcanoProteomeType is not None
                                    else ["clinical_information.pt_sbst_no=transcriptomevolcano.pt_sbst_no"]
                                    if volcanoTranscriptomeType is not None
                                    else ["clinical_information.pt_sbst_no=rna.pt_sbst_no"],
                                )
                                .values("id", "pt_sbst_no")
                                .distinct()
                            )
                        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                            error_message = "A database-related error occurred while processing your request."
                            if isinstance(e, IntegrityError):
                                error_message = "An integrity error occurred while processing your request."
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError(error_message)
                        except Exception as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError("An error occurred while processing your request.")

                    if filter_type == "boolean":
                        #'''
                        group_a_query_orm = base_query_orm.extra(
                            where=[f"{filter_column} = %s"],
                            params=["Y"] if project_id is None else ["1"],
                        )
                        group_b_query_orm = base_query_orm.extra(
                            where=[f"{filter_column} = %s"],
                            params=["N"] if project_id is None else ["0"],
                        )

                    if filter_type == "static":
                        if filter_column == "smok_yn":
                            group_a = []
                            group_b = []
                            if len(filter_group.get("group_a")) > 0:
                                for e in filter_group.get("group_a"):
                                    name, value = e.split("||")
                                    group_a.append(name + "='" + value + "'")

                            if len(filter_group.get("group_b")) > 0:
                                for e in filter_group.get("group_b"):
                                    name, value = e.split("||")
                                    group_b.append(name + "='" + value + "'")

                            #'''
                            group_a_query_s = " or ".join(group_a)
                            group_b_query_s = " or ".join(group_b)

                            group_a_query_orm = base_query_orm.extra(
                                where=[group_a_query_s]
                            )
                            group_b_query_orm = base_query_orm.extra(
                                where=[group_b_query_s]
                            )

                        elif (
                            filter_column == "her2_score" and main_filter_type == "dynamic" and project_id is None
                        ):
                            group_a = []
                            group_b = []
                            if len(filter_group.get("group_a")) > 0:
                                for e in filter_group.get("group_a"):
                                    for t in dynamic_her2[e]:
                                        group_a.append(
                                            filter_column + "= '" + t + "'")
                            if len(filter_group.get("group_b")) > 0:
                                for e in filter_group.get("group_b"):
                                    for t in dynamic_her2[e]:
                                        group_b.append(
                                            filter_column + "= '" + t + "'")
                            #'''
                            group_a_query_s = " or ".join(group_a)
                            group_b_query_s = " or ".join(group_b)

                            group_a_query_orm = base_query_orm.extra(
                                where=[group_a_query_s]
                            )
                            group_b_query_orm = base_query_orm.extra(
                                where=[group_b_query_s]
                            )

                        elif (
                            filter_column == "ki67_score" and main_filter_type == "dynamic" and project_id is None
                        ):
                            group_a = []
                            group_b = []
                            if len(filter_group.get("group_a")) > 0:
                                for e in filter_group.get("group_a"):
                                    v1, v2 = dynamic_ki67[e]
                                    group_a.append(
                                        "("
                                        + filter_column
                                        + " BETWEEN "
                                        + str(v1)
                                        + " and "
                                        + str(v2)
                                        + ")"
                                    )
                            if len(filter_group.get("group_b")) > 0:
                                for e in filter_group.get("group_b"):
                                    v1, v2 = dynamic_ki67[e]
                                    group_b.append(
                                        "("
                                        + filter_column
                                        + " BETWEEN "
                                        + str(v1)
                                        + " and "
                                        + str(v2)
                                        + ")"
                                    )

                            #'''
                            group_a_query_s = " or ".join(group_a)
                            group_b_query_s = " or ".join(group_b)

                            group_a_query_orm = base_query_orm.extra(
                                where=[group_a_query_s]
                            )
                            group_b_query_orm = base_query_orm.extra(
                                where=[group_b_query_s]
                            )
                        else:
                            group_a = []
                            group_b = []
                            if len(filter_group.get("group_a")) > 0:
                                for e in filter_group.get("group_a"):
                                    group_a.append(filter_column + "= '" + e + "'")
                            if len(filter_group.get("group_b")) > 0:
                                for e in filter_group.get("group_b"):
                                    group_b.append(filter_column + "= '" + e + "'")

                            #'''
                            group_a_query_s = " or ".join(group_a)
                            group_b_query_s = " or ".join(group_b)

                            group_a_query_orm = base_query_orm.extra(
                                where=[group_a_query_s]
                            )
                            group_b_query_orm = base_query_orm.extra(
                                where=[group_b_query_s]
                            )

                    if filter_type == "number":
                        if filter_column == "t_category":
                            #'''
                            number_query = f"({filter_column}=%s OR {filter_column}=%s)"
                            params1 = [filter_group.get(
                                "1_from"), filter_group.get("1_to")]
                            params2 = [filter_group.get(
                                "2_from"), filter_group.get("2_to")]

                            group_a_query_orm = base_query_orm.extra(
                                where=[number_query], params=params1
                            )
                            group_b_query_orm = base_query_orm.extra(
                                where=[number_query], params=params2
                            )

                        elif filter_column == "n_category":
                            if (filter_group.get("1_from") != filter_group.get("1_to")) or (
                                filter_group.get(
                                    "2_from") == filter_group.get("2_to")
                            ):
                                #'''
                                number_query = f"({filter_column}=%s OR {filter_column}=%s)"
                                params1 = [
                                    filter_group.get("1_from"),
                                    filter_group.get("1_to"),
                                ]
                                params2 = [
                                    filter_group.get("2_from"),
                                    filter_group.get("2_to"),
                                ]

                                group_a_query_orm = base_query_orm.extra(
                                    where=[number_query], params=params1
                                )
                                group_b_query_orm = base_query_orm.extra(
                                    where=[number_query], params=params2
                                )

                            else:
                                number_query = f"({filter_column}=%s)"
                                params1 = [filter_group.get("1_from")]
                                params2 = [filter_group.get("2_from")]

                                group_a_query_orm = base_query_orm.extra(
                                    where=[number_query], params=params1
                                )
                                group_b_query_orm = base_query_orm.extra(
                                    where=[number_query], params=params2
                                )

                        else:
                            number_query = f"({filter_column}>=%s AND {filter_column}<=%s)"
                            params1 = [filter_group.get(
                                "1_from"), filter_group.get("1_to")]
                            params2 = [filter_group.get(
                                "2_from"), filter_group.get("2_to")]
                            group_a_query_orm = base_query_orm.extra(
                                where=[number_query], params=params1
                            )
                            group_b_query_orm = base_query_orm.extra(
                                where=[number_query], params=params2
                            )

                    if main_filter_type == "static" and filter_column in volcano_static:
                        group1, group2 = volcano_static[filter_column]
                        group1 = group1.split(",")
                        group2 = group2.split(",")

                        formatted_list = [
                            f"{filter_column}='{item}'" for item in group1]
                        sub = " OR ".join(formatted_list)
                        group_a_query_orm = base_query_orm.extra(where=[sub])

                        formatted_list = [
                            f"{filter_column}='{item}'" for item in group2]
                        sub = " OR ".join(formatted_list)
                        group_b_query_orm = base_query_orm.extra(where=[sub])

                    if volcanoProteomeType is not None:
                        group_a_query_orm = group_a_query_orm.extra(
                            where=["proteomevolcano.type = %s"],
                            params=[volcanoProteomeType],
                        )
                        group_b_query_orm = group_b_query_orm.extra(
                            where=["proteomevolcano.type = %s"],
                            params=[volcanoProteomeType],
                        )
                    elif volcanoProteomeType is None and volcanoTranscriptomeType is not None:
                        group_a_query_orm = group_a_query_orm.extra(
                            where=["transcriptomevolcano.type = %s"],
                            params=[volcanoTranscriptomeType],
                        )
                        group_b_query_orm = group_b_query_orm.extra(
                            where=["transcriptomevolcano.type = %s"],
                            params=[volcanoTranscriptomeType],
                        )

                    group_a_query_response_orm = group_a_query_orm
                    group_b_query_response_orm = group_b_query_orm

                    for rnid in group_a_query_response_orm:
                        group_a_rnid_orm.add(rnid["pt_sbst_no"])
                    for rnid in group_b_query_response_orm:
                        group_b_rnid_orm.add(rnid["pt_sbst_no"])



                else:
                    if volcanoProteomeType is not None and volcanoProteomeType == "NT":
                        try:
                            group_a_query_response_orm = (
                                ClinicalInformation.objects.using(settings.DB)
                                .extra(
                                    select={
                                        "id": "1",
                                        "pt_sbst_no": "clinical_information.pt_sbst_no",
                                    },
                                    tables=["proteomevolcano"],
                                    where=[
                                        "clinical_information.pt_sbst_no=proteomevolcano.pt_sbst_no",
                                        "proteomevolcano.type='N'",
                                    ],
                                )
                                .values("id", "pt_sbst_no")
                            )
                            group_b_query_response_orm = (
                                ClinicalInformation.objects.using(settings.DB)
                                .extra(
                                    select={
                                        "id": "1",
                                        "pt_sbst_no": "clinical_information.pt_sbst_no",
                                    },
                                    tables=["proteomevolcano"],
                                    where=[
                                        "clinical_information.pt_sbst_no=proteomevolcano.pt_sbst_no",
                                        "proteomevolcano.type='T'",
                                    ],
                                )
                                .values("id", "pt_sbst_no")
                            )
                        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                            error_message = "A database-related error occurred while processing your request."
                            if isinstance(e, IntegrityError):
                                error_message = "An integrity error occurred while processing your request."
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError(error_message)
                        except Exception as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return HttpResponseServerError("An error occurred while processing your request.")

                        for rnid in group_a_query_response_orm:
                            group_a_rnid_orm.add(rnid["pt_sbst_no"])
                        for rnid in group_b_query_response_orm:
                            group_b_rnid_orm.add(rnid["pt_sbst_no"])
                    elif volcanoProteomeType is None :
                        if volcanoTranscriptomeType is not None and volcanoTranscriptomeType == "NT":
                            try:
                                group_a_query_response_orm = (
                                    ClinicalInformation.objects.using(settings.DB)
                                    .extra(
                                        select={
                                            "id": "1",
                                            "pt_sbst_no": "clinical_information.pt_sbst_no",
                                        },
                                        tables=["transcriptomevolcano"],
                                        where=[
                                            "clinical_information.pt_sbst_no=transcriptomevolcano.pt_sbst_no",
                                            "transcriptomevolcano.type='N'",
                                        ],
                                    )
                                    .values("id", "pt_sbst_no")
                                )
                                group_b_query_response_orm = (
                                    ClinicalInformation.objects.using(settings.DB)
                                    .extra(
                                        select={
                                            "id": "1",
                                            "pt_sbst_no": "clinical_information.pt_sbst_no",
                                        },
                                        tables=["transcriptomevolcano"],
                                        where=[
                                            "clinical_information.pt_sbst_no=transcriptomevolcano.pt_sbst_no",
                                            "transcriptomevolcano.type='T'",
                                        ],
                                    )
                                    .values("id", "pt_sbst_no")
                                )
                            except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
                                error_message = "A database-related error occurred while processing your request."
                                if isinstance(e, IntegrityError):
                                    error_message = "An integrity error occurred while processing your request."
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError(error_message)
                            except Exception as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("An error occurred while processing your request.")

                        for rnid in group_a_query_response_orm:
                            group_a_rnid_orm.add(rnid["pt_sbst_no"])
                        for rnid in group_b_query_response_orm:
                            group_b_rnid_orm.add(rnid["pt_sbst_no"])
                if len(group_a_rnid_orm) == 0 or len(group_b_rnid_orm) == 0:
                    return Response([], status=200)
                deseq_csv_file_path = None

                try:
                    if project_id is not None:
                        if viz_type == "transcriptome":
                            deseq_csv_file_path = f"{settings.BASE_DIR}/media/{username}/database/{project_id}_transcriptome.csv"
                        else:
                            deseq_csv_file_path = f"{settings.BASE_DIR}/media/{username}/database/{project_id}_proteome.csv"
                        if not os.path.exists(deseq_csv_file_path):
                            return Response({"message": "no data"}, status=204)
                except FileNotFoundError as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("The data file does not exist.")
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")

                response_list = self.deseq_calculations(
                    list(group_a_rnid_orm),
                    list(group_b_rnid_orm),
                    genes,
                    deseq_csv_file_path,
                    viz_type,
                    log2fc,
                    pval
                )
                if response_list is None:
                    return Response(status=status.HTTP_400_BAD_REQUEST)

                return Response(response_list, status=status.HTTP_200_OK)
            else:
                return Response({"message": "no data"}, status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            error_message = "A database-related error occurred while processing your request."
            if isinstance(e, IntegrityError):
                error_message = "An integrity error occurred while processing your request."
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError(error_message)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class IsSessionandSessionData(APIView):
    def get(self, request):

        session_key = request.session.session_key
        session_data = dict(request.session)
        user = request.user
        response_data = {"sessionid": session_key,
                         "session_data": session_data}
        if user.is_authenticated:
            response_data["username"] = user.username
            response_data["superuser"] = user.is_superuser
        return Response({"response_data": response_data}, status=200)

@method_decorator(csrf_protect, name="dispatch")
class ClinicalMaxMinInfo(APIView):
    def get(self, request):
        try:
            if "project_id" in request.GET:
                return Response({}, status=status.HTTP_200_OK)
            else:
                res = {}
                res["bmi_vl_max"] = ClinicalInformation.objects.using(
                    settings.DB
                ).aggregate(Max("bmi_vl"))["bmi_vl__max"]
                res["bmi_vl_min"] = ClinicalInformation.objects.using(
                    settings.DB
                ).aggregate(Min("bmi_vl"))["bmi_vl__min"]

                # res["mena_age_max"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Max("mena_age"))["mena_age__max"]
                # res["mena_age_min"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Min("mena_age"))["mena_age__min"]

                # res["feed_drtn_mnth_max"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Max("feed_drtn_mnth"))["feed_drtn_mnth__max"]
                # res["feed_drtn_mnth_min"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Min("feed_drtn_mnth"))["feed_drtn_mnth__min"]

                # res["her2_score_max"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Max("her2_score"))["her2_score__max"]
                # res["her2_score_min"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Min("her2_score"))["her2_score__min"]

                # res["ki67_score_max"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Max("ki67_score"))["ki67_score__max"]
                # res["ki67_score_min"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Min("ki67_score"))["ki67_score__min"]

                res["rlps_cnfr_drtn_max"] = ClinicalInformation.objects.using(
                    settings.DB
                ).aggregate(Max("rlps_cnfr_drtn"))["rlps_cnfr_drtn__max"]
                res["rlps_cnfr_drtn_min"] = ClinicalInformation.objects.using(
                    settings.DB
                ).aggregate(Min("rlps_cnfr_drtn"))["rlps_cnfr_drtn__min"]

                # res["er_score_max"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Max("er_score"))["er_score__max"]
                # res["er_score_min"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Min("er_score"))["er_score__min"]

                # res["pr_score_max"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Max("pr_score"))["pr_score__max"]
                # res["pr_score_min"] = ClinicalInformation.objects.using(
                #     settings.DB
                # ).aggregate(Min("pr_score"))["pr_score__min"]

                res["diag_age_max"] = ClinicalInformation.objects.using(
                    settings.DB
                ).aggregate(Max("diag_age"))["diag_age__max"]
                res["diag_age_min"] = ClinicalInformation.objects.using(
                    settings.DB
                ).aggregate(Min("diag_age"))["diag_age__min"]

                return Response({"data": res}, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database-related error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class Blast(APIView):
    def get(self, request):
        data = request.query_params
        container_name = data.get("container_name")

        if not container_name:
            return Response({"error": "Missing container_name parameter"}, status=400)

        user_project_directory = f"{settings.BASE_DIR}/media/Blast/outputfiles/{container_name}output_blast"

        try:
            docker_client = docker.from_env()
            container = docker_client.containers.get(container_name)
            container_state = container.attrs["State"]
            res = {}
            if container_state["Running"]:
                res = {"container_name": container_name, "status": "running", "msg": "Still Running"}
            else:
                res["status"] = "Done"
                res["msg"] = container.logs()
                res["user_project_directory"] = user_project_directory
                res["container_name"] = container_name

            return Response(res, status=200)
        except docker_errors.NotFound as e:
            return Response({"error": "Container not found"}, status=404)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        try:
            if request is not None:
                file_data = request.data["file"]
                database_type = request.data["database"]

                ct = datetime.now()
                ts = str(ct.timestamp()).replace('.', '-')

                file_name = 'user_input' + ts
                CONTAINER_NAME = "blast-prod-" + ts

                file_name = f"{file_name}{CONTAINER_NAME}" + '.fasta'

                if database_type == 'blastn':
                    database_directory = os.environ.get('BLAST_DATABASE')
                else:
                    database_directory = os.environ.get('BLAST_DATABASE')

                input_files_directory = os.environ.get('BLAST_INPUTFILES')

                output_files_directory = os.environ.get('BLAST_OUTPUTFILES')


                if not os.path.exists(input_files_directory):
                    os.makedirs(input_files_directory)

                if not os.path.exists(output_files_directory):
                    os.makedirs(output_files_directory)

                filepath = os.path.join(input_files_directory, file_name)

                if os.path.exists(filepath):
                    default_storage.delete(filepath)
                default_storage.save(filepath, file_data)

                docker_client = docker.from_env()

                volumes_to_mount = {
                    os.environ.get('BLAST'): {"bind": "/home/3bigs/", "mode": "rw"},
                    os.environ.get('BLAST_DATABASE'):{"bind":'/data/',"mode": "rw"},
                    os.environ.get('BLAST_INPUTFILES'):{"bind":'/inputfiles/',"mode": "rw"},
                    os.environ.get('BLAST_OUTPUTFILES'):{"bind":'/outputfiles/',"mode": "rw"}
                }
                image = "blast-prod:0.1"
                # args = f"/home/3bigs/interpro/interproscan-5.60-92.0/interproscan.sh  -t p -i /home/3bigs/ncc-backend/media/Interpro/files/{file_name} -f tsv  -o /home/3bigs/ncc-backend/media/Interpro/files/{CONTAINER_NAME}.tsv -pa -goterms -dp"
                args = f"blastn  -db /data/GCF_000001405.39_top_level -query /inputfiles/{file_name} -out /outputfiles/{CONTAINER_NAME}output_blast"
                r = docker_client.containers.run(
                    image,
                    args,
                    name=CONTAINER_NAME,
                    detach=True,
                    tty=True,
                    mem_limit="32g",
                    volumes=volumes_to_mount,
                )
                res = {"container_name": CONTAINER_NAME, "status": "running"}
                return Response(res, status=200)
            else:
                return Response(status=400)
        except docker_errors.APIError as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("Docker API error")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request")

@method_decorator(csrf_protect, name="dispatch")
class VcfMaf(APIView):
    def get(self, request):
        try:
            data = request.query_params
            container_name = data["container_name"]
            docker_client = docker.from_env()
            container = docker_client.containers.get(container_name)
            output_directory = f"{settings.BASE_DIR}/media/VcfMaf/output"
            container_state = container.attrs["State"]
            zip_file_name = request.session.get('zip_file_name')
            zip_file_url= f'{zip_file_name}' if zip_file_name else ''
            res = {
                "container_name": container_name,
            }
            if container_state["Running"]:
                res["status"] = "running"
                res["msg"] = "Still Running"
            else:
                res["status"] = "Done"
                res["msg"] = container.logs()
                res["zip_file_url"] = zip_file_url
                session_files = request.session.get('converted_files', [])
                for file in session_files:
                    file_path = os.path.join(output_directory, file)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                request.session['converted_files'] = []
            return Response(res, status=200)
        except docker_errors.NotFound as e:
            return Response({"error": "Container not found"}, status=404)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        try:
            if request is not None and request.user.username:

                ct = datetime.now()
                ts = str(ct.timestamp()).replace('.', '-')
                files = request.FILES
                user_project_directory = f"{settings.BASE_DIR}/media/VcfMaf"
                user_files_directory = os.path.join(
                    user_project_directory, "files")
                output_directory = f"{settings.BASE_DIR}/media/VcfMaf/output"


                if not os.path.exists(user_project_directory):
                    os.makedirs(user_project_directory)
                if not os.path.exists(user_files_directory):
                    os.makedirs(user_files_directory)
                if not os.path.exists(output_directory):
                    os.makedirs(output_directory)

                for file in os.listdir(output_directory):
                    file_path = os.path.join(output_directory, file)
                    os.remove(file_path)

                total_files = []
                for file in files:
                    file_data = request.FILES[file]
                    file_name = f'{file_data.name}'
                    filepath = os.path.join(user_files_directory, file_name)
                    if os.path.exists(filepath):
                        default_storage.delete(filepath)
                    default_storage.save(filepath, file_data)
                    file_path = f"{settings.BASE_DIR}/media/VcfMaf/files/{file_name}"
                    command = f"vim {file_path} -c 'set ff=unix' -c ':wq'"
                    total_files.append(file_name)
                    proc = Popen(command, shell=True, stdout=PIPE,
                        stdin=PIPE, stderr=STDOUT)
                    output = proc.communicate()

                docker_client = docker.from_env()
                volumes_to_mount = {
                    os.environ.get('TOOLSPATH'): {'bind': '/home/3bigs/', 'mode': 'rw'},
                }
                # print('--------volumes_to_mount',volumes_to_mount)

                image = "vcf2maf:1.6.21"
                converted_files = []
                containername = []
                CONTAINER_NAME = "vcf2maf-" + ts
                for file_data in total_files:
                    file_name = f"{file_data}"
                    file_path = os.path.join(user_files_directory, file_name)

                    container_name = f"{CONTAINER_NAME}_{os.path.splitext(file_name)[0]}_converted"
                    args = f"perl vcf2maf.pl --input-vcf /home/3bigs/ncc-backend/media/VcfMaf/files/{os.path.splitext(file_name)[0]}.vcf \
                    --output-maf /home/3bigs/ncc-backend/media/VcfMaf/output/{os.path.splitext(file_name)[0]}.maf \
                    --vep-path /home/vep/ --vep-data /home/3bigs/vcf2maf/ --species homo_sapiens \
                    --cache-version 100 --ref-fasta /home/3bigs/vcf2maf/hg38/hg38.fa \
                    --filter-vcf /home/3bigs/vcf2maf/ExAC_nonTCGA.r0.3.1.sites.vep.vcf.gz --ncbi-build GRCh38 "
                    containername.append(container_name)


                    auto_remove = True
                    r = docker_client.containers.run(
                        image,
                        args,
                        name=container_name,
                        detach=True,
                        tty=True,
                        mem_limit="32g",
                        volumes=volumes_to_mount,
                    )

                timeout = 1060  # maximum time to wait in seconds
                wait_time = 3  #time to wait between checks in seconds
                elapsed_time = 0

                while elapsed_time < timeout:
                    all_finished = True
                    for container_name in containername:
                        container = docker_client.containers.get(container_name)
                        container_state = container.attrs['State']

                        if container_state['Running']:
                            all_finished = False
                            break
                    if all_finished:
                        break
                    time.sleep(wait_time)
                    elapsed_time += wait_time

                if not all_finished:
                    return Response({"error": "File conversion timed out"}, status=500)

                converted_files = [f for f in os.listdir(output_directory) if f.endswith('.maf')]

                zip_file_name = f'maf_{ts}.zip'
                zip_file_path = os.path.join(output_directory, zip_file_name)
                with zipfile.ZipFile(zip_file_path, 'w') as zipf:
                    for file in converted_files:
                        file_path = os.path.join(output_directory, file)
                        zipf.write(file_path, arcname=os.path.basename(file_path))
                request.session['zip_file_name'] = zip_file_name
                res = {"container_name": containername, "status": "running","zip_file_name": zip_file_name}

                return Response(res, status=200)
            return Response(status=400)
        except docker_errors.APIError as docker_err:
            add_line_in_logger_file()
            logger.exception(docker_err)
            return HttpResponseServerError("Docker API error")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request")

@method_decorator(csrf_protect, name="dispatch")
class MatrixToMelted(APIView):
    def get(self, request):
        try:
            data = request.query_params
            container_name = data["container_name"]
            docker_client = docker.from_env()
            container = docker_client.containers.get(container_name)
            container_state = container.attrs["State"]
            res = {
                "container_name": container_name,
            }
            if container_state["Running"]:
                res["status"] = "running"
                res["msg"] = "Still Running"
            else:
                output_file = request.session.get(container_name, "Unknown")
                res["status"] = "Done"
                res["msg"] = container.logs()
                res["output_file"] = output_file
                request.session.pop(container_name, None)
            return Response(res, status=200)
        except docker_errors.NotFound as e:
            return Response({"error": "Container not found"}, status=404)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        try:
            if request is not None:

                ct = datetime.now()
                ts = str(ct.timestamp()).replace('.', '-')
                file_data = request.FILES["file"]
                file_name = file_data.name
                user_project_directory = f"{settings.BASE_DIR}/media/DfReconstruction"
                user_files_directory = os.path.join(
                    user_project_directory, "files")


                if not os.path.exists(user_project_directory):
                    os.makedirs(user_project_directory)
                if not os.path.exists(user_files_directory):
                    os.makedirs(user_files_directory)

                filepath = os.path.join(user_files_directory, file_name)
                if os.path.exists(filepath):
                    default_storage.delete(filepath)
                default_storage.save(filepath, file_data)

                docker_client = docker.from_env()
                volumes_to_mount = {
                    os.environ.get('DFRECONSTRUCTION'): {'bind': '/dfreconstruction/', 'mode': 'rw'}
                    # '/home/ubuntu/sohel/ncc-backend/media/DfReconstruction/': {'bind': '/dfreconstruction/', 'mode': 'rw'},
                }

                image='df_recon:0.1'
                CONTAINER_NAME = "dfrecon-" + ts
                args = f"python3 df_reconstruction.py -i /dfreconstruction/files/{file_name} -s off"

                auto_remove = True
                r = docker_client.containers.run(
                    image,
                    args,
                    name=CONTAINER_NAME,
                    detach=True,
                    tty=True,
                    mem_limit="32g",
                    volumes=volumes_to_mount,
                )
                output_file_name = file_name.replace('.tsv', '') + "_transformed.tsv"
                request.session[CONTAINER_NAME] = output_file_name
                res = {"container_name": CONTAINER_NAME, "status": "running","output_file": output_file_name}
                return Response(res, status=200)
            else:
                return Response(status=400)
        except docker_errors.APIError as f:
            add_line_in_logger_file()
            logger.exception(f)
            return HttpResponseServerError("Docker API error")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request")

@method_decorator(csrf_protect, name="dispatch")
class InterproFile(APIView):
    def get(self, request):
        data = request.query_params
        container_name = data.get("container_name")

        if not container_name:
            return Response({"error": "Missing container_name parameter"}, status=400)

        try:
            docker_client = docker.from_env()
            container = docker_client.containers.get(container_name)
            container_state = container.attrs["State"]

            if container_state["Running"]:
                res = {"container_name": container_name, "status": "running", "msg": "Still Running"}
            else:
                file_path = os.path.join(settings.MEDIA_ROOT, "Interpro/files", f"{container_name}.tsv")

                with open(file_path, "r+") as f:
                    s = f.read()
                    f.seek(0)
                    f.write("Sequence Accession\tSequence MD5 digest\tSequence Length\tAnalysis\tSignature Accession\tSignature Description\tStart Location\tStop Location\tScore\tStatus - Match status\tRun Date\tInterpro Accession\tInterpro Description\tGO Annotations\tOther Pathways\t\n" + s)

                res = {"container_name": container_name, "status": "Done", "msg": container.logs()}

            return Response(res, status=200)
        except docker_errors.NotFound as e:
            return Response({"error": "Container not found"}, status=404)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        try:
            if request is not None:
                ct = datetime.now()
                ts = str(ct.timestamp()).replace('.', '-')

                file_data = request.data["file"]
                filename_without_spaces = request.data["filename"].strip().replace(" ", "")
                file_name = f"{filename_without_spaces}_{ts}"
                user_project_directory = f"{settings.BASE_DIR}/media/Interpro"
                user_files_directory = os.path.join(
                    user_project_directory, "files")

                if not os.path.exists(user_project_directory):
                    os.makedirs(user_project_directory)

                if not os.path.exists(user_files_directory):
                    os.makedirs(user_files_directory)

                filepath = os.path.join(user_files_directory, file_name)
                if os.path.exists(filepath):
                    default_storage.delete(filepath)
                default_storage.save(filepath, file_data)

                docker_client = docker.from_env()
                image = "interpro:0.2"
                CONTAINER_NAME = "interpro-" + ts
                volumes_to_mount = {}
                if os.environ.get('PRODUCTION') == 'True':
                    volumes_to_mount = {
                        os.environ.get('TOOLSPATH'): {"bind": "/home/3bigs/", "mode": "rw"},
                    }
                    args = f"{os.environ.get('INTERPRO_REQUIRED_FILES')}  -t p -i {os.environ.get('INTERPRO')}{file_name} -f tsv  -o {os.environ.get('INTERPRO')}{CONTAINER_NAME}.tsv -pa -goterms -dp"
                    # args = f"/home/3bigs/interpro/interproscan-5.60-92.0/interproscan.sh  -t p -i /home/3bigs/ncc-backend/media/Interpro/files/{file_name} -f tsv  -o /home/3bigs/ncc-backend/media/Interpro/files/{CONTAINER_NAME}.tsv -pa -goterms -dp"

                else:
                    volumes_to_mount = {
                            os.environ.get('TOOLSPATH'): {"bind": "/home/3bigs/", "mode": "rw"},
                            os.environ.get('INTERPRO_REQUIRED_FILES'): {"bind": "/interpro/", "mode": "rw"},
                        }
                    args = f"{os.environ.get('INTERPRO_REQUIRED_FILES')}  -t p -i {os.environ.get('INTERPRO')}{file_name} -f tsv  -o {os.environ.get('INTERPRO')}{CONTAINER_NAME}.tsv -pa -goterms -dp"
                    #  /interpro/interproscan-5.57-90.0/interproscan.sh
                    # docker run -v /home/ubuntu/sohel:/home/3bigs/  -v /home/ubuntu/efs/mani/interpro/:/interpro  interpro:0.2 /interpro/interproscan-5.57-90.0/interproscan.sh -t p -i /home/3bigs/ncc-backend/media/Interpro/files/insulin-nucleotide.fasta_1700805543-73715 -f tsv -o /home/ubuntu/sohel/ncc-backend/media/Interpro/files/outputinterpro.tsv -pa -goterms -dp
                    #docker run -v /home/ubuntu/sohel:/home/3bigs/  -v /home/ubuntu/efs/mani/interpro/:/interpro  interpro:0.2 /interpro/interproscan-5.57-90.0/interproscan.sh -t p -i /home/3bigs/ncc-backend/media/Interpro/files/insulin-nucleotide.fasta_1700805983-004384 -f tsv -o /home/3bigs/ncc-backend/media/Interpro/files/abcd.tsv -pa -goterms -dp
                _ = docker_client.containers.run(
                        image,
                        args,
                        name=CONTAINER_NAME,
                        detach=True,
                        tty=True,
                        mem_limit="32g",
                        volumes=volumes_to_mount,
                    )
                res = {"container_name": CONTAINER_NAME, "status": "running"}
                return Response(res, status=200)
            else:
                return Response(status=400)
        except docker_errors.APIError as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("Docker API error")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request")

@method_decorator(csrf_protect, name="dispatch")
class MafMerger (APIView):
    def get(self, request):
        if request is not None and request.user.username:
            try:
                data = request.query_params
                container_name = data["container_name"]
                docker_client = docker.from_env()
                container = docker_client.containers.get(container_name)
                container_state = container.attrs["State"]

                username = request.user.username
                user_project_directory = f"media/MAFMerger/{username}/"

                res = {
                    "container_name": container_name,
                }
                if container_state["Running"]:
                    res["status"] = "running"
                    res["msg"] = "Still Running"
                else:
                    res["status"] = "Done"
                    res["msg"] = container.logs()
                    res["user_project_directory"] = user_project_directory
                return Response(res, status=200)
            except docker_errors.NotFound as e:
                return Response({"error": "Container not found"}, status=404)
            except Exception as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("An error occurred while processing your request.")
        else:
            return Response(status=400)


    def post(self, request):

        if request is not None and request.user.username:
            try:
                username = request.user.username
                files = request.FILES

                user_project_directory = f"{settings.BASE_DIR}/media/MAFMerger/{username}"


                if not os.path.exists(user_project_directory):
                    os.makedirs(user_project_directory)
                ct = datetime.now()
                ts = str(ct.timestamp()).replace('.', '-')
                CONTAINER_NAME = "maf-merger-prod-" + ts
                if username:
                    total_files = []
                    for file in files:
                        file_data = request.FILES[file]
                        file_name = file_data.name.strip().replace(" ", "") + f"_{ts}"
                        filepath = os.path.join(user_project_directory, file_name)
                        if os.path.exists(filepath):
                            default_storage.delete(filepath)
                        default_storage.save(filepath, file_data)
                        total_files.append(f"{file_name}")

                docker_client = docker.from_env()
                # Binding -> we are binding the sohel folder to mafmerger inside app of docker.
                # so we wont loose maf_merger.py which was in app and we can access all the files also.

                volumes_to_mount = {
                    os.environ.get('TOOLSPATH'): {'bind': '/app/mafmerger/', 'mode': 'rw'}
                }
                image = "maf-merger-prod:0.1"

                files_str = ' '.join(total_files)
                args = f"python maf_merger.py -i {files_str} -p /app/mafmerger/ncc-backend/media/MAFMerger/{username} -o {CONTAINER_NAME}.maf -t {CONTAINER_NAME}.tsv"
                r = docker_client.containers.run(
                    image,
                    args,
                    name=CONTAINER_NAME,
                    detach=True,
                    tty=True,
                    mem_limit="32g",
                    volumes=volumes_to_mount,
                )
                res = {"container_name": CONTAINER_NAME, "status": "running"}
                return Response(res, status=200)
            except docker_errors.APIError as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("Docker API error")
            except Exception as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("An error occurred while processing your request")
        else:
            return Response(status=400)

@method_decorator(csrf_protect, name="dispatch")
class REFVERCONVERTER (APIView):
    def get(self, request):
        if request is not None and request.user.username:
            try:
                data = request.query_params
                container_name = data["container_name"]
                docker_client = docker.from_env()
                container = docker_client.containers.get(container_name)
                container_state = container.attrs["State"]
                zip_file_name = request.session.get('zip_file_name')
                zip_file_url= f'{zip_file_name}' if zip_file_name else ''
                user_project_directory = f"media/RefVerConverter/importantFiles/"
                output_directory = f"{settings.BASE_DIR}/media/RefVerConverter/output"
                res = {
                    "container_name": container_name,
                }
                if container_state["Running"]:
                    res["status"] = "running"
                    res["msg"] = "Still Running"
                else:
                    res["status"] = "Done"
                    res["msg"] = container.logs()
                    res["zip_file_url"] = zip_file_url

                    # Clean up files related to the session
                    session_files = request.session.get('converted_files', [])
                    for file in session_files:
                        file_path = os.path.join(output_directory, file)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    request.session['converted_files'] = []
                return Response(res, status=200)
            except docker_errors.NotFound as e:
                return Response({"error": "Container not found"}, status=404)
            except Exception as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("An error occurred while processing your request.")
        else:
            return Response(status=400)

    @staticmethod
    def is_alnum_dash(name):
        return all(c.isalnum() or c in {'-', '_', '.'} for c in name)

    def post(self, request):
        if request is not None and request.user.username:
            try:
                username = request.user.username
                hg19 = request.data.get('hg19', 'false').lower() == 'true'
                hg38 = request.data.get('hg38', 'false').lower() == 'true'
                conversion = '19to38' if hg19 else '38to19' if hg38 else None

                files = request.FILES
                ct = datetime.now()
                ts = str(ct.timestamp()).replace('.', '-')
                CONTAINER_NAME = "liftover-prod-" + ts

                user_project_directory = f"{settings.BASE_DIR}/media/RefVerConverter/input"
                output_directory = f"{settings.BASE_DIR}/media/RefVerConverter/output"

                if not os.path.exists(user_project_directory):
                    os.makedirs(user_project_directory)
                if not os.path.exists(output_directory):
                    os.makedirs(output_directory)

                if username:
                    total_files = []
                    for file in files:
                        file_data = request.FILES[file]
                        file_name = f'{file_data.name}'
                        filepath = os.path.join(user_project_directory, file_name)
                        if os.path.exists(filepath):
                            default_storage.delete(filepath)
                        default_storage.save(filepath, file_data)
                        total_files.append(file_name)

                docker_client = docker.from_env()
                # Binding -> we are binding the sohel folder to refverconverter inside app of docker.
                # so we wont lose refverconverter.py which was in app and we can access all the files also.
                volumes_to_mount = {
                    os.environ.get('REFVERCONVERTER'): {'bind': '/refverconverter/', 'mode': 'rw'}
                }
                image = "vcf-converter-prod:0.1"
                containername=[]
                for file_name in total_files:
                    base_name = os.path.splitext(file_name)[0]
                    if not self.is_alnum_dash(base_name):
                        return Response({"message": f"Invalid container name Only [a-z, A-Z, 0-9, -_. ] are allowed."}, status=400)

                    file_cont_name = f'{CONTAINER_NAME}{base_name}_converted_{conversion}'
                    container_name = f"{file_cont_name}"
                    container_args = f"python3 /refverconverter/importantFiles/vcf_converter.py -i {file_name} -p /refverconverter -c {conversion} -oid {container_name}"
                    containername.append(container_name)
                    auto_remove = True
                    docker_client.containers.run(
                        image,
                        container_args,
                        name=container_name,
                        detach=True,
                        tty=True,
                        mem_limit="32g",
                        volumes=volumes_to_mount,
                    )
                time.sleep(3)
                converted_files = [f for f in os.listdir(output_directory) if f.endswith(f'_converted_{conversion}.vcf')]
                session_files = request.session.get('converted_files', [])
                session_files.extend(converted_files)
                request.session['converted_files'] = session_files
                zip_file_name = f'{conversion}_converted_{ts}.zip'
                zip_file_path = os.path.join(output_directory, zip_file_name)
                with zipfile.ZipFile(zip_file_path, 'w') as zipf:
                    for file in converted_files:
                        file_path = os.path.join(output_directory, file)
                        zipf.write(file_path, arcname=os.path.basename(file_path))
                request.session['zip_file_name'] = zip_file_name
                res = {"container_name": containername, "status": "running","zip_file_name": zip_file_name}
                return Response(res, status=200)

            except docker_errors.APIError as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("Docker API error")
            except Exception as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("An error occurred while processing your request")
        else:
            return Response(status=400)



@api_view(["POST", "GET"])
def generateReport(request):
    if request.method == "POST":
        TablesData = request.data.get("GeneandMutationList")
        user_project_directory = f"{settings.BASE_DIR}/static"
        user_files_directory = os.path.join(
            user_project_directory, "Imagefiles")
        all_Image_Data = {}
        for k, v in TablesData.items():
            File_name = k + request.data.get("unq") + ".txt"
            db_path = os.path.join(user_files_directory, File_name)
            f = open(db_path, "r")
            data = f.read()
            all_Image_Data[k] = data
            f.close()
            if os.path.exists(db_path):
                os.remove(db_path)
        t = {}

        for k, v in TablesData.items():
            gene = k
            mutations = v
            if len(mutations) == 1:
                query = f"SELECT 1 as id,hugo_symbol,variant_classification,dbsnp_rs,diseasename,drugname,sourceurl\
                        from genevariantsankey where hugo_symbol='{gene}' and variant_classification='{mutations[0]}' order by  pmid_count desc "
            else:
                m = "','".join(mutations)
                m = "'" + m + "'"
                query = f"SELECT 1 as id,hugo_symbol,variant_classification,dbsnp_rs,diseasename,drugname,sourceurl \
                from genevariantsankey where hugo_symbol='{gene}' and variant_classification IN ({m}) order by  pmid_count desc "
            rows = Fusion.objects.raw(query)
            tmp_table = {}
            for each in rows:
                kt = (
                    each.hugo_symbol
                    + "||"
                    + each.variant_classification
                    + "||"
                    + each.dbsnp_rs
                    + "||"
                    + each.diseasename
                )
                if kt not in tmp_table:
                    tmp_table[kt] = []
                tmp_table[kt].append(each.drugname)

            dTable = []
            for k, v in tmp_table.items():
                r = k.split("||")
                drugs = tmp_table[k]
                drugs = [i for i in drugs if i]
                temp_drugs = ""
                if len(drugs) > 0:
                    if len(drugs) == 1:
                        temp_drugs = drugs[0]
                    else:
                        temp_drugs = ", ".join(list(set(drugs)))
                if r[0] != "" and r[1] != "" and r[2] != "" and r[3] != "":
                    dTable.append(
                        {
                            "hugo_symbol": r[0],
                            "variant_classification": r[1],
                            "dbsnp_rs": r[2],
                            "diseasename": r[3],
                            "drugname": temp_drugs,
                        }
                    )
            t[gene] = dTable
        data = {
            "key": "brst_001",
            "headers": ["Cancer Major Genes", "DNA Mutation", "RNA", "Proteome"],
            "columns": [
                "geneName",
                "Yes",
                "No",
                "High",
                "Intermediate",
                "Low",
                "High",
                "Intermediate",
                "Low",
            ],
            "rows": request.data.get("rows"),
            "BasicInformation": request.data.get("BasicInformation"),
            "img_data_into_list": all_Image_Data,
            "tableData": t,
        }
        context = data

        template = get_template("SankeyReport/SankeyReport.html")
        html = template.render(context)
        user_uniq_id = str(uuid.uuid4())
        # Changed from file to filename
        result = open(
            f"{settings.BASE_DIR}/media/report{user_uniq_id}.pdf", "wb")
        pdf = pisa.pisaDocument(six.StringIO(str(html)), result)
        result.close()
        # f = open(f'{settings.BASE_DIR}/media/report{user_uniq_id}.pdf', 'rb')
        # return Response({"res":f'media/report{user_uniq_id}.pdf'})
        return Response({"res": f"media/report{user_uniq_id}.pdf"})

    elif request.method == "GET":
        BasicInformation = {
            "Sex": "F",
            "Age Of Diagnosis (1st Day Of Diagnosis)": "35",
            "BMI (1st Day Of Diagnosis)": "27.23",
            "Alcohol Consumtion": "No",
            "Smoking Status": "No",
        }

        rows = advance_information_rows
        GeneandMutationList = {"TP53": ["Frame_Shift_Del"]}
        TablesData = GeneandMutationList
        user_project_directory = f"{settings.BASE_DIR}/static"
        user_files_directory = os.path.join(
            user_project_directory, "Imagefiles")
        all_Image_Data = {}
        for k, v in TablesData.items():
            all_Image_Data[k] = ""

        t = {}

        for k, v in TablesData.items():
            gene = k
            mutations = v
            if len(mutations) == 1:
                query = f"SELECT 1 as id,hugo_symbol,variant_classification,dbsnp_rs,diseasename,drugname,sourceurl\
                        from genevariantsankey where hugo_symbol='{gene}' and variant_classification='{mutations[0]}' order by  pmid_count desc "
            else:
                m = "','".join(mutations)
                m = "'" + m + "'"
                query = f"SELECT 1 as id,hugo_symbol,variant_classification,dbsnp_rs,diseasename,drugname,sourceurl \
                from genevariantsankey where hugo_symbol='{gene}' and variant_classification IN ({m}) order by  pmid_count desc "
            rows_ = Fusion.objects.raw(query)
            tmp_table = {}
            for each in rows_:
                kt = (
                    each.hugo_symbol
                    + "||"
                    + each.variant_classification
                    + "||"
                    + each.dbsnp_rs
                    + "||"
                    + each.diseasename
                )
                if kt not in tmp_table:
                    tmp_table[kt] = []
                tmp_table[kt].append(each.drugname)

            dTable = []
            for k, v in tmp_table.items():
                r = k.split("||")
                drugs = tmp_table[k]
                drugs = [i for i in drugs if i]
                temp_drugs = ""
                if len(drugs) > 0:
                    if len(drugs) == 1:
                        temp_drugs = drugs[0]
                    else:
                        temp_drugs = ", ".join(list(set(drugs)))
                if r[0] != "" and r[1] != "" and r[2] != "" and r[3] != "":
                    dTable.append(
                        {
                            "hugo_symbol": r[0],
                            "variant_classification": r[1],
                            "dbsnp_rs": r[2],
                            "diseasename": r[3],
                            "drugname": temp_drugs,
                        }
                    )
            t[gene] = dTable
        data = {
            "key": "brst_001",
            "headers": ["Cancer Major Genes", "DNA Mutation", "RNA", "Proteome"],
            "columns": [
                "geneName",
                "Yes",
                "No",
                "High",
                "Intermediate",
                "Low",
                "High",
                "Intermediate",
                "Low",
            ],
            "rows": rows,
            "BasicInformation": BasicInformation,
            "img_data_into_list": all_Image_Data,
            "tableData": t,
        }
        context = data
        pdf = downloadPDF("SankeyReport/SankeyReport.html", context)
        return HttpResponse(pdf, content_type="application/pdf")


# %%