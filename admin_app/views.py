import array
import datetime
import logging
import random
import uuid
from datetime import datetime, timezone
import pytz
import time
from admin_app.models import *
from admin_app.serializers import *
from app.constants import add_line_in_logger_file
# File Imports
from app.models import DownloadVisualization, Profile, SessionDetails
# Django Imports
from django import template
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail as sm
from django.core.paginator import Paginator
from django.db.models import Q
from django.db.utils import DatabaseError, IntegrityError
from django.http import HttpResponseServerError, JsonResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.text import slugify
from django.utils.translation import activate, get_language
from django.utils.translation import gettext
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
# Rest Imports
from rest_framework.views import APIView
from user_data_visualization.models import UserDataExtension
from .forms import CkEditorForm

User = get_user_model()
logger = logging.getLogger(__name__)
# translation

register = template.Library()


def translate(language):
    cur_language = get_language()
    try:
        activate(language)
        text = gettext("hello")
    finally:
        activate(cur_language)
    return text


def get_password():

    MAX_LEN = 12

    # declare arrays of the character that we need in out password
    # Represented as chars to enable easy string concatenation
    DIGITS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    LOCASE_CHARACTERS = [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
    ]

    UPCASE_CHARACTERS = [
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "M",
        "N",
        "O",
        "P",
        "Q",
        "R",
        "S",
        "T",
        "U",
        "V",
        "W",
        "X",
        "Y",
        "Z",
    ]

    SYMBOLS = [
        "@",
        "#",
        "$",
        "%",
        "=",
        ":",
        "?",
        ".",
        "/",
        "|",
        "~",
        ">",
        "*",
        "(",
        ")",
        "<",
    ]

    # combines all the character arrays above to form one array
    COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

    # randomly select at least one character from each character set above
    rand_digit = random.choice(DIGITS)
    rand_upper = random.choice(UPCASE_CHARACTERS)
    rand_lower = random.choice(LOCASE_CHARACTERS)
    rand_symbol = random.choice(SYMBOLS)

    # combine the character randomly selected above
    # at this stage, the password contains only 4 characters but
    # we want a 12-character password
    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    # now that we are sure we have at least one character from each
    # set of characters, we fill the rest of
    # the password length by selecting randomly from the combined
    # list of character above.
    for x in range(MAX_LEN - 4):
        temp_pass = temp_pass + random.choice(COMBINED_LIST)

        # convert temporary password into array and shuffle to
        # prevent it from having a consistent pattern
        # where the beginning of the password is predictable
        temp_pass_list = array.array("u", temp_pass)
        random.shuffle(temp_pass_list)

    # traverse the temporary password array and append the chars
    # to form the password
    password = ""
    for x in temp_pass_list:
        password = password + x

    return password


@login_required(login_url="/login/")
def google_analytics_dashboard(request):
    keys = {
        "type": "service_account",
        "project_id": "ncc-k-core",
        "private_key_id": "a4d526492af972b2876060d490077b4bb7b48726",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDKbJ+iqGFWG3F3\nHoxq3fSqaIhj1W+o6v6BwKfRNOBpJ0ge0YHtv3RvAGqXBIKc0a9Bi4r54F6auVJK\nWp9lbC31qzQhFQWwReeh1Xv9+iKu26RERXyVUjf2g04PbWVKQSLpinRlg4NahfS8\nMXTph9dvXT8yBFWGW9h5Xg4JyqccBpl0Fno772xluT9zoXonSypZt3k+PLYx/VcT\n+SknuFlRNWpjiYteP3llZTewjOdf6nLp8iZYhIBL1eKRWGwwJdv1lUYvIC9OHTjV\nKIjAFAZIji8j3d26HNNOVF1Vs4Pw3URGDTBCxFVguoR9hqufaRi0iCZ/3lM/WREw\nuZpIee53AgMBAAECggEAZBArH4CF0UdyoPRIbGF42y4eUd+FuWYk1mYybt/pGQHy\njE17oVeVinOVvT5dBIFA1bFRy3DGw0xd6eR/S+cclwcBF2NpcvgzZxP9nZBjSbXI\nr3j7+2JvyJui4ExvGDQ3umOXY0EOExcJ4me+R9y/Oc1J+oMa9fZ7/Y7peJylW9vk\nAfqtTYsYdA4of776L18YTx/j1KIvJsesxFTXGxgf8u2N9OJvdMHk87k+4+OnGqB1\ndchkAvvYn8011IIzJj6ncI2pCl5nYVDpLqzfCbR7nSwBID3S4CC1sn+1niLW2Ttc\nDGonFOPj6A9Gdsql2q8HFkacD5RKGfFDcR3eMhvTJQKBgQDt/hXSFz+m/hbE72GI\nCZqjNxg1y/GosW4QNna+xTau03YIDpXzMCARGs4GABahlzhBtcyXezdPOEKthCjE\nIUoVYLbw74fq9flVHF1CxxPgfh3B4QXKgkiJlEldrskjyjrRTPtPkdoYq4p0SKSr\nOEzFzTsjx8n1hgPYdSP/E9ye1QKBgQDZvZUJOgPghASiSd+Qhb32xS+usICTReFQ\n4I4KP53xeamFGv+cX+k1kiV6a0dkvPoNmFCUItpWg/CpBVTMitwQC6vwzgO6vVL6\nZGtH8ZGJHmnpwrE8Qgm/O6tn+gKhlGOT8DK6CaTQoJnze2Fi0xn8lCZIpagyay6s\nFJpZWIN2GwKBgQC5CvHUZBcttCnn/WgL6cu+U7wTN/sxeqNlH7O8KIKX8/q10QFu\nEGEea4T8zVzLT1SCYuQsc7VRdyEA4N0BghCkBoq3UsaPPakbL+6jWT5vMh/Y+ykR\nh7L2pcFVge0KUtbgncZY28KDo/0G5OSD7EZlFWmCLHku2YBr8MiIL9098QKBgQCu\nHuTnk/U1vVzXSqv1Ln5SsC0JTSwEmYUs3+W2XFk5mUjuoEB4FFqx9ET0OIXHETgF\nVyBY1eYz+R6iixjc2M5SJoNA9f4VfwC0K0l/JrZzKFcaEA8bWNPikRzo8QzZmYhn\n7VUjYELkcwmpo6ilFptZWD+lKJPwfbW89lzXxeiasQKBgFdO44Sfk1jX7xGrbHmn\nn0yq+be5wPvFWqD2ep+B77SZDOWrkraAAk2Ny3OqQt02BYpccMmxHnb4n8wa7VZk\neOnUvH25pDtlKsMsxvgYBH8z874DjkYa8dHuON01eCpfwknWKUHXGGz++oTy+i7A\ntLOdoQAmku5gce/N4tvu1+Lg\n-----END PRIVATE KEY-----\n",
        "client_email": "k-core@ncc-k-core.iam.gserviceaccount.com",
        "client_id": "115041239749814268740",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/k-core%40ncc-k-core.iam.gserviceaccount.com",
    }

    ANALYTICS_CREDENTIALS_JSON = keys
    # ANALYTICS_VIEW_ID = 'ga:274836782'
    ANALYTICS_VIEW_ID = "ga:176053970"

    SCOPE = "https://www.googleapis.com/auth/analytics.readonly"
    _key_data = ANALYTICS_CREDENTIALS_JSON

    # _credentials = SignedJwtAssertionCredentials(_key_data['client_email'], _key_data['private_key'], SCOPE)

    return render(
        request,
        "googleanalytics.html",
        {
            "token": _credentials.get_access_token().access_token,
            "view_id": ANALYTICS_VIEW_ID,
        },
    )


@login_required(login_url="/login/")  # redirect when user is not logged in
def homePage(request):
    # return render(request, 'index.html', {'frontend_domain':settings.FRONTEND_DOMAIN})
    return render(request, "index.html", {"frontend_domain": ""})


@login_required(login_url="/login/")
def code_management(request):
    return render(request, "CommonManagement/code_management.html", {})


@login_required(login_url="/login/")
@csrf_exempt
def menu_management(request):
    return render(request, "CommonManagement/menu_management.html", {})


@login_required(login_url="/login/")
@csrf_exempt
def permission_management(request):
    return render(request, "CommonManagement/permission_management.html", {})


@login_required(login_url="/login/")
@csrf_exempt
def user_management(request):
    user_obj = User.objects.all().order_by("-id")
    paginator = Paginator(user_obj, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    index_list = [*range(1, 10 + 1)]
    if page_number is not None and float(page_number) >= 1:
        index_list = [
            *range((int(page_number) - 1) * 10 + 1, (int(page_number) - 1) * 10 + 11)
        ]
    context = {"user_data": page_obj, "index_list": index_list}
    return render(request, "UserManagement/user_management.html", context)


@login_required(login_url="/login/")
@csrf_exempt
def user_management_list(request):
    try:
        draw = 10
        if request.GET.get("draw"):
            draw = int(request.GET.get("draw"))
        start = 0
        if request.GET.get("start"):
            start = int(request.GET.get("start"))
        length = 10
        if request.GET.get("length"):
            length = int(request.GET.get("length"))
        search = request.GET.get("search[value]")

        user_data = User.objects
        total = User.objects
        if search:
            user_data = user_data.filter(
                Q(username__icontains=search)
                | Q(first_name__icontains=search)
            )
            total = total.filter(
                Q(username__icontains=search)
                | Q(first_name__icontains=search)
            )

        user_data = user_data.values(
            "username",
            "first_name",
            "email",
            "requested_date",
            "approved_date",
            "id",
        )
        user_data = user_data.all().order_by("-id")[start : start + length]
        total = total.count()

        data = list(user_data)
        result_list = {
            "data": data,
            "draw": draw,
            "recordsTotal": len(data),
            "recordsFiltered": total,
        }
        return JsonResponse(result_list, safe=False)
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def check_user_id(request):
    user_id = ""
    if request.method == "POST":
        if request.POST.get("userid"):
            user_id = request.POST.get("userid")
        try:
            user_obj = User.objects.get(username=user_id)
            return JsonResponse({"user_exist": True}, safe=False)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return JsonResponse({"user_exist": False}, safe=False)


@login_required(login_url="/unauthorized/")
@csrf_exempt
def change_password(request, pk):
    user_id = ""
    new_password = ""
    if request.method == "POST":
        if request.POST.get("userid"):
            user_id = request.POST.get("userid")
        if request.POST.get("new_password"):
            new_password = request.POST.get("new_password")
        if request.POST.get("reconfirm_password"):
            reconfirm_password = request.POST.get("reconfirm_password")

        try:
            obj = User.objects
            pass_obj = obj.get(id=int(user_id))
            pass_obj.set_password(new_password)
            pass_obj.save()
            return JsonResponse({"status": True}, safe=False)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return JsonResponse({"status": False}, safe=False)
    else:
        context = {"user_id": pk}
        return render(request, "ResetPassword/reset_password.html", context)


@login_required(login_url="/unauthorized/")
@csrf_exempt
def user_management_register(request):
    if request.method == "POST":
        try:
            user_id = request.POST.get("userid")
            first_name = request.POST.get("firstname")
            email = request.POST.get("email")
            status = request.POST.get("status")
            mand_fields_count = 0
            try:
                user = User.objects.get(username=user_id)
                return JsonResponse({"msg": "User Already Exist"})
            except User.DoesNotExist:
                user = None

            if user is None:
                if user_id != "":
                    user_obj = User(username=user_id)
                    if first_name != "":
                        user_obj.first_name = first_name
                    else:
                        mand_fields_count += 1

                    if email != "":
                        user_obj.email = email
                    else:
                        mand_fields_count += 1

                    if status == "True":
                        user_obj.is_active = True
                    else:
                        user_obj.is_active = False

                    password = get_password()
                    user_obj.set_password(password)
                else:
                    mand_fields_count += 1
                if mand_fields_count == 0:
                    ct = datetime.now(pytz.timezone('Asia/Seoul'))
                    unique_pin = f"{random.randint(0, 9999):04}"
                    unique_token = uuid.uuid4()
                    context = {
                        "username": user_id,
                        "set_password": f"{settings.FRONTEND_DOMAIN}set-password/{unique_token}/",
                        "unique_pin":unique_pin,
                        "frontend_domain":f"{settings.FRONTEND_DOMAIN}",
                        "datetime":datetime.now(pytz.timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M")
                        }
                    if email != "":
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
                                subject=f"[K-CORE] 회원가입 승인 요청 (분석접수번호: {user_id})",
                                message="New User Registration",
                                html_message=render_to_string("UserAdminEmails/newregistrationadmin.html", context),
                                from_email=settings.SENDER_EMAIL,
                                recipient_list=[
                                    settings.SENDER_EMAIL,
                                    # "ncdc@ncc.re.kr",
                                    # "nhwoo@3bigs.com",
                                ],
                                fail_silently=False,
                            )
                            if user_mail > 0 and admin_mail > 0:
                                user_obj.save()
                                try:
                                    profile_obj1 = Profile.objects.create(
                                    user=user_obj,
                                    forget_password_token=unique_token,
                                    created_at=ct,
                                    unique_pin=unique_pin,
                                )
                                    profile_obj1.save()
                                except Exception as e:
                                    add_line_in_logger_file()
                                    logger.exception(e)
                                    return JsonResponse({"msg": "Internal Error"})
                            else:
                                return JsonResponse({"msg": "Error in sending mail"})
                        except Exception as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return JsonResponse({"msg": "Error in sending mail"})

                    return JsonResponse({"success": True})
                return JsonResponse({"msg": "enter mandatory fields"})
            return JsonResponse({"msg": "enter mandatory fields"})
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        return render(request, "UserManagement/user_management_register.html", {})

@login_required(login_url="/unauthorized/")
@csrf_exempt
def usermanagement_update(request):
    if request.method == "POST":
        user_id = request.POST.get("id")
        user_name = request.POST.get("userid")
        first_name = request.POST.get("firstname")
        email = request.POST.get("email")
        status = request.POST.get("status")
        mand_fields = 0

        edit_obj = User.objects.get(id=user_id)
        unique_pin = ""

        try:
            profile_obj = Profile.objects.get(user=edit_obj)
            unique_pin = profile_obj.unique_pin
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            profile_obj = None

        if user_name != "":
            edit_obj.username = user_name
            if edit_obj.username != user_name:
                return JsonResponse({"msg": "ID already Exists"})

        else:
            mand_fields += 1
        if email != "":
            edit_obj.email = email
        else:
            mand_fields += 1
        if first_name != "":
            edit_obj.first_name = first_name
        else:
            mand_fields += 1
        if status == "True":
            edit_obj.is_active = True
            edit_obj.approved_date = datetime.now(pytz.timezone('Asia/Seoul'))
        else:
            edit_obj.is_active = False

        if mand_fields <= 0:
            edit_obj.save()
            # Add email feature
            if status == "True":
                if email != "":
                    context = {
                        "username": user_name,
                        "unique_pin": unique_pin,
                        "datetime": datetime.now(pytz.timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M")
                        }
                    _ = sm(
                        subject="K-CORE 회원가입 승인 완료",
                        message="User Activation",
                        html_message=render_to_string("userActive.html", context),
                        from_email=settings.SENDER_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )
            else:
                if email != "":
                    context = {"username": user_name,
                               "unique_pin": unique_pin,
                               "datetime": datetime.now(pytz.timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M")
                               }
                    _ = sm(
                        subject="K-CORE 이용자 계정 만료 안내",
                        message="User Deactivated",
                        html_message=render_to_string(
                            "UserAdminEmails/userDeActiveUser.html", context),
                        from_email=settings.SENDER_EMAIL,
                        recipient_list=[email],
                        fail_silently=False,
                    )

            return JsonResponse({"status": "Edited"})
        return JsonResponse({"msg": "Enter Mandaotry Fields"})


@login_required(login_url="/unauthorized/")
@csrf_exempt
def user_management_edit(request, pk):
    if request.method == "POST":
        user_name = request.POST.get("userName")
        first_name = request.POST.get("userName")
        email = request.POST.get("email")
        status = request.POST.get("status")
        edit_obj = User.objects.get(id=pk)
        if edit_obj.username != user_name:
            return JsonResponse({"message": "ID already Exists"})
        edit_obj.username = user_name
        edit_obj.email = email
        edit_obj.first_name = first_name

        if status == "True":
            edit_obj.is_active = True
        else:
            edit_obj.is_active = False

        edit_obj.save()
        context = {"user_data": edit_obj}
        context["edit"] = False
        return redirect(settings.FORCE_SCRIPT_NAME + "user-management")
    else:
        if "delete" in request.GET and request.GET.get("delete") == "True":
            obj = User.objects
            delete_obj = obj.get(id=pk)
            delete_obj.delete()
            return redirect(settings.FORCE_SCRIPT_NAME + "user_management")
        user_obj = User.objects.get(id=pk)
        context = {"user_data": user_obj}
        if "edit" in request.GET and request.GET.get("edit") == "True":
            context["edit"] = True
        else:
            context["edit"] = False
        return render(
            request, "UserManagement/user_management_update.html", context
        )

@login_required(login_url="/unauthorized/")
@csrf_exempt
def delete_user_management_user(request, pk):
    try:
        user_obj = User.objects
        delete_obj = user_obj.get(id=pk)
        profile_obj = Profile.objects.filter(user=delete_obj).first()
        if profile_obj:
            try:
                profile_obj.delete()
            except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
                add_line_in_logger_file()
                logger.exception(e)
            except Exception as e:
                add_line_in_logger_file()
                logger.exception(e)
        delete_obj.delete()
        return redirect(settings.FORCE_SCRIPT_NAME + "user-management")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return redirect(settings.FORCE_SCRIPT_NAME + "user-management")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def notice_list(request):
    try:
        draw = 10
        if request.GET.get("draw"):
            draw = int(request.GET.get("draw"))
        start = 0
        if request.GET.get("start"):
            start = int(request.GET.get("start"))
        length = 10
        if request.GET.get("length"):
            length = int(request.GET.get("length"))
        select = request.GET.get("schKeyWord")
        searched_term = request.GET.get("schKeyValue")
        notice_data = CommunityManagementNotice.objects
        if select == "title":
            notice_data = notice_data.filter(title__icontains=searched_term)
        elif select == "detail":
            notice_data = notice_data.filter(content__icontains=searched_term)
        elif select == "reguser":
            notice_data = notice_data.filter(writer__icontains=searched_term)

        total = CommunityManagementNotice.objects

        notice_data = notice_data.values("title", "writer", "updated_on", "id")
        notice_data = notice_data.all().order_by("-id")[start : start + length]
        total = notice_data.count()

        data = list(notice_data)
        result_list = {
            "data": data,
            "draw": draw,
            "recordsTotal": len(data),
            "recordsFiltered": total,
        }
        return JsonResponse(result_list, safe=False)
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")

@login_required(login_url="/unauthorized/")
@csrf_exempt
def notice(request):
    if request.method == "POST":
        try:
            select = request.POST.get("schKeyWord")
            searched_term = request.POST.get("schKeyValue")
            community_obj = CommunityManagementNotice.objects
            if select == "title":
                community_data = community_obj.filter(title__icontains=searched_term)
            elif select == "detail":
                community_data = community_obj.filter(content__icontains=searched_term)
            elif select == "reguser":
                community_data = community_obj.filter(writer__icontains=searched_term)
            community_data.order_by("-id")
            paginator = Paginator(community_data, 10)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/Notice/notice.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        try:
            community_data = CommunityManagementNotice.objects.all().order_by("-id")
            paginator = Paginator(community_data, 10)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/Notice/notice.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@login_required(login_url="/unauthorized/")
@csrf_exempt
def notice_form(request):
    try:
        if request.method == "POST":
            user_ = request.user
            username = request.POST.get("usernm")
            title = request.POST.get("title")
            content = request.POST.get("detail")
            com = CommunityManagementNotice(
                user=user_, writer=username, title=title, content=content
            )
            com.save()
            community_data = CommunityManagementNotice.objects.all().order_by("-id")
            paginator = Paginator(community_data, 10)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/Notice/notice.html", context)
        form = CkEditorForm()
        return render(
            request, "CommunityManagement/Notice/notice_form.html", {"form": form}
        )
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def edit_notice_form(request, pk):
    if request.method == "POST":
        try:
            title = request.POST.get("title")
            writer = request.POST.get("usernm")
            content = request.POST.get("detail")
            status = request.POST.get("status")
            is_active_status = False

            all_notice_details = CommunityManagementNotice.objects.all()

            if status is not None:
                is_active_status = True
                for change_active_status in all_notice_details:
                    if change_active_status.id is not pk:
                        change_active_status.is_active = False
                        change_active_status.save()

            if status is None:
                is_active_status = False

            notice_detail = CommunityManagementNotice.objects.get(id=pk)
            notice_detail.title = title
            notice_detail.writer = writer
            notice_detail.content = content
            notice_detail.is_active = is_active_status
            notice_detail.save()
            context = {"notice_detail": notice_detail}
            context["edit"] = False
            return render(request, "CommunityManagement/Notice/edit_form.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        try:
            if "delete" in request.GET and request.GET.get("delete") == "True":
                notice_obj = CommunityManagementNotice.objects
                delete_obj = notice_obj.get(id=pk)
                delete_obj.delete()
                return redirect(settings.FORCE_SCRIPT_NAME + "notice")
            notice_detail = CommunityManagementNotice.objects.get(id=pk)
            context = {"notice_detail": notice_detail}
            if "edit" in request.GET and request.GET.get("edit") == "True":
                context["edit"] = True
            else:
                context["edit"] = False
            return render(request, "CommunityManagement/Notice/edit_form.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def delete_notice_form(request, pk):
    try:
        notice_obj = CommunityManagementNotice.objects
        delete_obj = notice_obj.get(id=pk)
        delete_obj.delete()
        return redirect(settings.FORCE_SCRIPT_NAME + "notice")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return redirect(settings.FORCE_SCRIPT_NAME + "notice")



@login_required(login_url="/unauthorized/")
@csrf_exempt
def q_and_a_list(request):
    try:
        draw = 10
        if request.GET.get("draw"):
            draw = int(request.GET.get("draw"))
        start = 0
        if request.GET.get("start"):
            start = int(request.GET.get("start"))
        length = 10
        if request.GET.get("length"):
            length = int(request.GET.get("length"))
        select = request.GET.get("schKeyWord")
        searched_term = request.GET.get("schKeyValue")
        notice_data = CommunityManagementQnA.objects
        if select == "title":
            notice_data = notice_data.filter(title__icontains=searched_term)
        elif select == "detail":
            notice_data = notice_data.filter(content__icontains=searched_term)
        elif select == "reguser":
            notice_data = notice_data.filter(writer__icontains=searched_term)

        total = CommunityManagementQnA.objects

        notice_data = notice_data.values("title", "writer", "updated_on", "id")
        notice_data = notice_data.all().order_by("-id")[start : start + length]
        total = notice_data.count()

        data = list(notice_data)
        result_list = {
            "data": data,
            "draw": draw,
            "recordsTotal": len(data),
            "recordsFiltered": total,
        }
        return JsonResponse(result_list, safe=False)
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")

@login_required(login_url="/unauthorized/")
@csrf_exempt
def q_and_a(request):
    if request.method == "POST":
        try:
            select = request.POST.get("schKeyWord")
            searched_term = request.POST.get("schKeyValue")
            community_obj = CommunityManagementQnA.objects
            if select == "title":
                community_data = community_obj.filter(title__icontains=searched_term)
            elif select == "detail":
                community_data = community_obj.filter(content__icontains=searched_term)
            elif select == "reguser":
                community_data = community_obj.filter(writer__icontains=searched_term)
            community_data.order_by("-id")
            paginator = Paginator(community_data, 2)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/Q&A/q_and_a.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        try:
            community_data = CommunityManagementQnA.objects.all().order_by("-id")
            paginator = Paginator(community_data, 2)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/Q&A/q_and_a.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def q_and_a_form(request):
    try:
        if request.method == "POST":
            user_ = request.user
            username = request.POST.get("usernm")
            title = request.POST.get("title")
            content = request.POST.get("detail")
            com = CommunityManagementQnA(
                user=user_, writer=username, title=title, content=content
            )
            com.save()
            community_data = CommunityManagementQnA.objects.all().order_by("-id")
            paginator = Paginator(community_data, 2)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/Q&A/q_and_a.html", context)
        form = CkEditorForm()
        return render(request, "CommunityManagement/Q&A/q_and_a_form.html", {"form": form})
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")



@login_required(login_url="/unauthorized/")
@csrf_exempt
def edit_q_and_a_form(request, pk):
    if request.method == "POST":
        try:
            title = request.POST.get("title")
            writer = request.POST.get("usernm")
            content = request.POST.get("detail")
            q_and_a_detail = CommunityManagementQnA.objects.get(id=pk)
            q_and_a_detail.title = title
            q_and_a_detail.writer = writer
            q_and_a_detail.content = content
            q_and_a_detail.save()

            context = {"q_and_a_detail": q_and_a_detail}
            context["edit"] = False
            return render(request, "CommunityManagement/Q&A/edit_form.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        try:
            if "delete" in request.GET and request.GET.get("delete") == "True":
                obj = CommunityManagementQnA.objects
                delete_obj = obj.get(id=pk)
                delete_obj.delete()
                return redirect(settings.FORCE_SCRIPT_NAME + "q_and_a")
            else:
                q_and_a_detail = CommunityManagementQnA.objects.get(id=pk)
                context = {"q_and_a_detail": q_and_a_detail}
                if "edit" in request.GET and request.GET.get("edit") == "True":
                    context["edit"] = True
                else:
                    context["edit"] = False
                return render(request, "CommunityManagement/Q&A/edit_form.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@login_required(login_url="/unauthorized/")
@csrf_exempt
def delete_q_and_a_form(request, pk):
    try:
        obj = CommunityManagementQnA.objects
        delete_obj = obj.get(id=pk)
        delete_obj.delete()
        return redirect(settings.FORCE_SCRIPT_NAME + "q_and_a")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return redirect(settings.FORCE_SCRIPT_NAME + "q_and_a")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def faq_list(request):
    try:
        draw = 10
        if request.GET.get("draw"):
            draw = int(request.GET.get("draw"))
        start = 0
        if request.GET.get("start"):
            start = int(request.GET.get("start"))
        length = 10
        if request.GET.get("length"):
            length = int(request.GET.get("length"))
        select = request.GET.get("schKeyWord")
        searched_term = request.GET.get("schKeyValue")
        faq_data = CommunityManagementFaq.objects
        if select == "title":
            faq_data = faq_data.filter(title__icontains=searched_term)
        elif select == "detail":
            faq_data = faq_data.filter(content__icontains=searched_term)
        elif select == "reguser":
            faq_data = faq_data.filter(writer__icontains=searched_term)

        total = CommunityManagementFaq.objects
        faq_data = faq_data.values("title", "writer", "updated_on", "id")
        faq_data = faq_data.all().order_by("-id")[start : start + length]
        total = faq_data.count()

        data = list(faq_data)
        result_list = {
            "data": data,
            "draw": draw,
            "recordsTotal": len(data),
            "recordsFiltered": total,
        }
        return JsonResponse(result_list, safe=False)
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def faq(request):
    if request.method == "POST":
        try:
            select = request.POST.get("schKeyWord")
            searched_term = request.POST.get("schKeyValue")
            community_obj = CommunityManagementFaq.objects
            if select == "title":
                community_data = community_obj.filter(title__icontains=searched_term)
            elif select == "detail":
                community_data = community_obj.filter(content__icontains=searched_term)
            elif select == "reguser":
                community_data = community_obj.filter(writer__icontains=searched_term)
            community_data.order_by("-id")
            paginator = Paginator(community_data, 2)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/FAQ/faq.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        try:
            community_data = CommunityManagementFaq.objects.all().order_by("-id")
            paginator = Paginator(community_data, 2)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/FAQ/faq.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def faq_form(request):
    try:
        if request.method == "POST":
            user_ = request.user
            username = request.POST.get("usernm")
            title = request.POST.get("title")
            content = request.POST.get("detail")
            com = CommunityManagementFaq(
                user=user_, writer=username, title=title, content=content
            )
            com.save()
            community_data = CommunityManagementFaq.objects.all().order_by("-id")
            paginator = Paginator(community_data, 2)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            context = {"community_data": page_obj}
            return render(request, "CommunityManagement/FAQ/faq.html", context)
        form = CkEditorForm()
        return render(request, "CommunityManagement/FAQ/faq_form.html",{"form": form})
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def edit_faq_form(request, pk):
    if request.method == "POST":
        try:
            title = request.POST.get("title")
            writer = request.POST.get("usernm")
            content = request.POST.get("detail")

            faq_detail = CommunityManagementFaq.objects.get(id=pk)
            faq_detail.title = title
            faq_detail.writer = writer
            faq_detail.content = content
            faq_detail.save()
            context = {"faq_detail": faq_detail}
            context["edit"] = False
            return render(request, "CommunityManagement/FAQ/edit_form.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        try:
            if "delete" in request.GET and request.GET.get("delete") == "True":
                obj = CommunityManagementFaq.objects
                delete_obj = obj.get(id=pk)
                delete_obj.delete()
                return redirect(settings.FORCE_SCRIPT_NAME + "faq")
            faq_detail = CommunityManagementFaq.objects.get(id=pk)
            context = {"faq_detail": faq_detail}
            if "edit" in request.GET and request.GET.get("edit") == "True":
                context["edit"] = True
            else:
                context["edit"] = False
                return render(request, "CommunityManagement/FAQ/edit_form.html", context)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
@csrf_exempt
def delete_faq_form(request, pk):
    try:
        obj = CommunityManagementFaq.objects
        delete_obj = obj.get(id=pk)
        delete_obj.delete()
        return redirect(settings.FORCE_SCRIPT_NAME + "faq")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return redirect(settings.FORCE_SCRIPT_NAME + "faq")


@login_required(login_url="/unauthorized/")
def bulletin(request):
    return render(request, "OperationManagement/bulletin_board_management.html", {})


@login_required(login_url="/unauthorized/")
def bulletin_create(request):
    return render(request, "OperationManagement/create_bulletin_board.html", {})


@login_required(login_url="/unauthorized/")
def openapi(request):
    return render(request, "ServiceManagement/openApi.html", {})


@login_required(login_url="/unauthorized/")
def log_list(request):
    return render(request, "Log/log_list.html", {})

@login_required(login_url="/unauthorized/")
def project_list(request):
    return render(request, "ProjectManagement/project_list.html", {})

@login_required(login_url="/unauthorized/")
def project_data(request):
    try:
        draw = 10
        if request.GET.get("draw"):
            draw = int(request.GET.get("draw"))
        start = 0
        if request.GET.get("start"):
            start = int(request.GET.get("start"))
        length = 10
        if request.GET.get("length"):
            length = int(request.GET.get("length"))
        search = request.GET.get("search[value]")

        project_data = UserDataExtension.objects
        total = UserDataExtension.objects
        if search:
            project_data = project_data.filter(
                Q(project_name__icontains=search)
                | Q(username__icontains=search)
                | Q(reason_for_extension__icontains=search)

            )
            total = total.filter(
                Q(project_name__icontains=search)
                | Q(username__icontains=search)
                | Q(reason_for_extension__icontains=search)
            )

        project_data = project_data.values(
            "username",
            "project_name",
            "uploaded_date",
            "extended_on",
            "reason_for_extension",
            "deleted_on",
        )

        project_data = project_data.all().order_by("-id")[start : start + length]
        total = total.count()

        data = list(project_data)
        for record in data:
            if record["uploaded_date"]:
                record["uploaded_date"] = record["uploaded_date"].strftime("%d/%m/%Y")
            if record["extended_on"]:
                record["extended_on"] = record["extended_on"].strftime("%d/%m/%Y")
            if record["deleted_on"]:
                record["deleted_on"] = record["deleted_on"].strftime("%d/%m/%Y")

        result_list = {
            "data": data,
            "draw": draw,
            "recordsTotal": len(data),
            "recordsFiltered": total,
        }
        return JsonResponse(result_list, safe=False)
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
def log_data(request):
    try:
        draw = 10
        if request.GET.get("draw"):
            draw = int(request.GET.get("draw"))
        start = 0
        if request.GET.get("start"):
            start = int(request.GET.get("start"))
        length = 10
        if request.GET.get("length"):
            length = int(request.GET.get("length"))
        search = request.GET.get("search[value]")

        log_data = SessionDetails.objects
        total = SessionDetails.objects
        if search:
            log_data = log_data.filter(
                Q(url__icontains=search)
                | Q(category__icontains=search)
                | Q(user__username__icontains=search)
            )
            total = total.filter(
                Q(url__icontains=search)
                | Q(category__icontains=search)
                | Q(user__username__icontains=search)
            )

        if (
            request.GET.get("from")
            and request.GET.get("from") != ""
            and request.GET.get("to")
            and request.GET.get("to") != ""
        ):
            log_data = log_data.filter(
                visitedDate__range=[request.GET.get("from"), request.GET.get("to")]
            )
            total = total.filter(
                visitedDate__range=[request.GET.get("from"), request.GET.get("to")]
            )

        log_data = log_data.values(
            "session_id",
            "user__username",
            "url",
            "start_time",
            "end_time",
            "ip_address",
            "visitedDate",
            "category"
        )
        log_data = log_data.all().order_by("-id")[start : start + length]
        total = total.count()

        data = list(log_data)
        result_list = {
            "data": data,
            "draw": draw,
            "recordsTotal": len(data),
            "recordsFiltered": total,
        }
        return JsonResponse(result_list, safe=False)
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")


# redirect when user is not logged in
@login_required(login_url="/unauthorized/")
def capture_log_list(request):
    return render(request, "Log/download_report.html", {})

@login_required(login_url="/unauthorized/")
def get_session_stats(request):
    sessions = Session.objects.filter(expire_date__gte=datetime.now(timezone.utc))
    logged_in_user_ids = [session.get_decoded().get('_auth_user_id') for session in sessions]

    logged_in_users = User.objects.filter(id__in=logged_in_user_ids)
    logged_out_users = User.objects.exclude(id__in=logged_in_user_ids)

    logged_in_users_count = logged_in_users.count()
    logged_out_users_count = logged_out_users.count()
    total_users_count = User.objects.count()

    data = {
        "logged_in": logged_in_users_count,
        "logged_out": logged_out_users_count,
        "total_users": total_users_count
    }

    return JsonResponse(data)

@login_required(login_url="/unauthorized/")
def analysis_stats_view(request):
    # Get today's date
    today = datetime.now().date()
    # today = datetime.now(pytz.timezone('Asia/Seoul')).date()

    sessions = SessionDetails.objects.filter(
        Q(url__icontains="multidata") | Q(url__icontains="singledata"),
        visitedDate=today
    ).select_related('user').order_by('-visitedDate', '-start_time')[:10]

    data = {
        "sessions": list(sessions.values(
            'user__username', 'url', 'visitedDate', 'start_time'
        ))
    }

    return JsonResponse(data)

@login_required(login_url="/unauthorized/")
def session_management_view(request):
    return render(request, "SessionMgmt/session_mgmt.html", {})

def capture_log_data(request):
    try:
        draw = 10
        if request.GET.get("draw"):
            draw = int(request.GET.get("draw"))
        start = 0
        if request.GET.get("start"):
            start = int(request.GET.get("start"))
        length = 10
        if request.GET.get("length"):
            length = int(request.GET.get("length"))
        search = request.GET.get("search[value]")

        category = ''
        if request.GET.get("category"):
            category = request.GET.get("category")

        download_viz = DownloadVisualization.objects
        total = DownloadVisualization.objects
        if search:
            download_viz = download_viz.filter(
                Q(category__icontains=search) | Q(chart_name__icontains = search)
            )
            total = total.filter(
                Q(category__icontains=search) | Q(chart_name__icontains = search)
            )

        if category:
            download_viz = download_viz.filter(
                Q(category__icontains=category)
            )
            total = total.filter(
                Q(category__icontains=category)
            )

        if (
            request.GET.get("from")
            and request.GET.get("from") != ""
            and request.GET.get("to")
            and request.GET.get("to") != ""
        ):
            download_viz = download_viz.filter(
                created_on__range=[request.GET.get("from"), request.GET.get("to")]
            )
            total = total.filter(
                created_on__range=[request.GET.get("from"), request.GET.get("to")]
            )

        download_viz = download_viz.values(
            "user__username",
            "created_on",
            "chart_name",
            "project_id",
            "category"
        )
        download_viz = download_viz.all().order_by("-id")[start : start + length]
        total = total.count()

        data = list(download_viz)
        result_list = {
            "data": data,
            "draw": draw,
            "recordsTotal": len(data),
            "recordsFiltered": total,
        }
        return JsonResponse(result_list, safe=False)
    except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")
    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return HttpResponseServerError("An error occurred while processing your request.")


@login_required(login_url="/unauthorized/")
def data_application(request):
    return render(request, "DataApplicationManagement/data_application_list.html", {})


@csrf_exempt
def login_view(request):
    if request.method == "POST":
        try:
            username = request.POST.get("userid")
            password = request.POST.get("passwd")
            user = authenticate(username=username, password=password)
            if user is not None:
                return redirect(settings.FORCE_SCRIPT_NAME + "home")
            else:
                context = {"message": "invalid Username or Password"}
                return render(request, "Authentication/login.html", context)
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
    else:
        return render(request, "Authentication/login.html", {})


def logoutView(request):
    logout(request)
    return render(request, "Authentication/login.html", {})


def UnauthorizedView(request):
    return render(request, "Authentication/unauthenticated.html", {})


class DeleteUser(APIView):
    def post(self, request):
        try:
            data = request.data
            if data:
                try:
                    user = User.objects.get(username=data["id"])
                except User.DoesNotExist:
                    user = None
                if not user:
                    content = {"message": "User Doesnt Exist"}
                    return Response(content, status=200)
                try:
                    User.objects.delete(username=data["id"])
                    content = {"message": "User Deleted Successfully"}
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    content = {"message": "Error Deleting User"}

                    return Response(content, status=200)
            else:
                return Response(status=400)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

class FaqApi(APIView):
    def get(self, request):
        try:
            if "id" in request.GET:
                id_ = request.GET.get("id")
                faq_data = CommunityManagementFaq.objects.get(id=id_)
                serializer = FaqSerializer(faq_data)
                return Response(serializer.data, status=200)
            faq_data = CommunityManagementFaq.objects.all().order_by("-id")
            per_page = 10
            if "per_page" in request.GET:
                per_page = request.GET.get("per_page")
            paginator = Paginator(faq_data, per_page)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            serializer = FaqSerializer(page_obj, many=True)
            if serializer.data:
                return Response({
                        "data": serializer.data,
                        "total": page_obj.paginator.count,
                        "page": int(page_number),
                        "total_pages": paginator.num_pages
                    },status=200)
            return Response({"data":""},status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        type = request.data.get("type")
        search = request.data.get("searchTerm")
        community_obj = CommunityManagementFaq.objects
        if type == "title":
            community_data = community_obj.filter(title__icontains=search).order_by(
                "-id"
            )
        elif type == "content":
            community_data = community_obj.filter(content__icontains=search).order_by(
                "-id"
            )
        elif type == "writer":
            community_data = community_obj.filter(writer__icontains=search).order_by(
                "-id"
            )

        if "per_page" in request.GET:
            per_page = request.GET.get("per_page")
        paginator = Paginator(community_data, per_page)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)
        serializer = FaqSerializer(page_obj, many=True)
        if serializer.data:
            return Response(
                {"data": serializer.data, "total": page_obj.paginator.count}, status=200
            )
        return Response(status=204)

class NoticeApi(APIView):
    def get(self, request):
        try:
            if "id" in request.GET:
                id_ = request.GET.get("id")
                notice_data = CommunityManagementNotice.objects.get(id=id_)
                serializer = NoticeSerializer(notice_data)
                return Response(serializer.data, status=200)
            notice_data = CommunityManagementNotice.objects.all().order_by("-id")
            per_page = 10
            if "per_page" in request.GET:
                per_page = request.GET.get("per_page")
            paginator = Paginator(notice_data, per_page)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            serializer = NoticeSerializer(page_obj, many=True)
            if serializer.data:
                return Response({
                        "data": serializer.data,
                        "total": page_obj.paginator.count,
                        "page": int(page_number),
                        "total_pages": paginator.num_pages
                        },
                    status=200,
                )
            return Response(status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        try:
            type = request.data.get("type")
            search = request.data.get("searchTerm")
            community_obj = CommunityManagementNotice.objects
            if type == "title":
                community_data = community_obj.filter(title__icontains=search).order_by(
                    "-id"
                )
            elif type == "content":
                community_data = community_obj.filter(content__icontains=search).order_by(
                    "-id"
                )
            elif type == "writer":
                community_data = community_obj.filter(writer__icontains=search).order_by(
                    "-id"
                )

            if "per_page" in request.GET:
                per_page = request.GET.get("per_page")
            paginator = Paginator(community_data, per_page)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            serializer = NoticeSerializer(page_obj, many=True)
            if serializer.data:
                return Response(
                    {"data": serializer.data, "total": page_obj.paginator.count}, status=200
                )
            return Response(status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

class QA_Api(APIView):
    def get(self, request):
        try:
            if "id" in request.GET:
                id_ = request.GET.get("id")
                notice_data = CommunityManagementQnA.objects.get(id=id_)
                serializer = QASerializer(notice_data)
                return Response(serializer.data, status=200)
            qa_data = CommunityManagementQnA.objects.all().order_by("-id")
            per_page = 10
            if "per_page" in request.GET:
                per_page = request.GET.get("per_page")
            paginator = Paginator(qa_data, per_page)
            page_number = request.GET.get("page")
            page_obj = paginator.get_page(page_number)
            serializer = QASerializer(page_obj, many=True)
            if serializer.data:
                return Response(
                    {"data": serializer.data,
                        "total": page_obj.paginator.count,
                        "page": int(page_number),
                    "total_pages": paginator.num_pages

                    },
                    status=200,
                )
            return Response(status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

    def post(self, request):
        try:
            if "new" in request.data:
                user = User.objects.get(username="yasin")
                title = request.data.get("title")
                writer = request.data.get("writer")
                content = request.data.get("content")
                slug = slugify(title)
                exist_q_and_a = CommunityManagementQnA.objects.filter(
                    url_slug=slug
                ).order_by("-id")
                if not exist_q_and_a:
                    community_obj = CommunityManagementQnA(
                        user=user, title=title, writer=writer, content=content
                    )
                    community_obj.save()
                    content = {"message": ""}
                    return Response(content, status=200)
                content = {"message": "title already exist"}
                return Response(content, status=200)
            else:
                type = request.data.get("type")
                search = request.data.get("searchTerm")
                community_obj = CommunityManagementQnA.objects
                if type == "title":
                    community_data = community_obj.filter(title__icontains=search).order_by(
                        "-id"
                    )
                elif type == "content":
                    community_data = community_obj.filter(
                        content__icontains=search
                    ).order_by("-id")
                elif type == "writer":
                    community_data = community_obj.filter(
                        writer__icontains=search
                    ).order_by("-id")

                if "per_page" in request.GET:
                    per_page = request.GET.get("per_page")
                paginator = Paginator(community_data, per_page)
                page_number = request.GET.get("page")
                page_obj = paginator.get_page(page_number)
                serializer = QASerializer(page_obj, many=True)
                if serializer.data:
                    return Response(
                        {"data": serializer.data, "total": page_obj.paginator.count},
                        status=200,
                    )
                return Response(status=204)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

class LogManagement(APIView):

    """Store User Logmanagement in Database.
    Parameters
    ----------
    self, request : `Json request`
        @ will get the user activity, SessionId, visited Page, Starttime, Endtime, url of the page,
            time they spent, Username, Visited Date.

    Returns
    -------
    returnValue : `Response Code`
        If response data is inserted succesfully into SessionDetails database
            Response is 200, else Response is 500.
    """

    def post(self, request):
        if request is not None and request.data is not None:
            try:
                for obj in request.data:
                    # logger.error(f'session obj is= {obj}')
                    session_id = obj.get("sessionId")
                    url = obj.get("url")
                    start_time = obj.get("startTime")
                    end_time = obj.get("endTime")
                    visitedDate = datetime.now(pytz.timezone('Asia/Seoul')).date()
                    category = obj.get("category")
                    ip_address = request.META["REMOTE_ADDR"]
                    if request.user.is_anonymous:
                        try:
                            try:
                                user_obj = User.objects.get(username='AnonymousUser')
                            except User.DoesNotExist:
                                user_obj = User.objects.create(
                                    username='AnonymousUser',
                                    email="AnonymousUser@3bigs.com"
                                    )
                                user_obj.is_active = False
                                user_obj.save()
                            sessiondetails_obj = SessionDetails.objects.create(
                                user=user_obj,
                                session_id=session_id,
                                url=url,
                                start_time=start_time,
                                end_time=end_time,
                                ip_address=ip_address,
                                latitude=0.0,
                                langitude=0.0,
                                visitedDate=visitedDate,
                                category=category,
                            )
                            sessiondetails_obj.save()
                        except Exception as e:
                            add_line_in_logger_file()
                            logger.exception(e)
                            return Response(status=500)
                    else:
                        sessiondetails_obj = SessionDetails.objects.create(
                            user=request.user,
                            session_id=session_id,
                            url=url,
                            start_time=start_time,
                            end_time=end_time,
                            ip_address=ip_address,
                            latitude=0.0,
                            langitude=0.0,
                            visitedDate=visitedDate,
                            category=category,
                        )
                        sessiondetails_obj.save()
                return Response(status=200)
            except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("An error occurred while processing your request.")
            except Exception as e:
                add_line_in_logger_file()
                logger.exception(e)
                return HttpResponseServerError("An error occurred while processing your request.")

class CaptureLogManagement(APIView):
    """
    API view for recording and handling download visualization requests.

    This view allows users to record and handle requests for downloading visualizations.
    It records user details, IP address, and the date of the download request.

    Methods:
        post(request): Handle the POST request for recording download visualization requests.
    """

    def post(self, request):
        """
        Handle the POST request for recording download visualization requests.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            Response: A JSON response indicating the success
            of the request or any validation errors.
        """
        ip_address = request.META["REMOTE_ADDR"]

        try:
            log_obj = DownloadVisualization.objects.create(
                user =request.user,
                ip_address=ip_address,
                chart_name = request.data["chart_name"],
                project_id = request.data["project_id"].strip(),
                category=request.data["location"]
                )
            log_obj.save()
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        return Response({"message": "created"}, status=200)
