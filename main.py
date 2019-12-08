import os
import sys
import shlex
import subprocess

from flask import Flask, render_template, request

init = "terraform init"
init_shlex = shlex.split(init)
init_process = subprocess.Popen(init_shlex)

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/vuldescript")
def vuldescript():
    return render_template("vulnerabilitydesc.html")

@app.route("/vulform")
def vulform():
    return render_template("vulnerabilityform.html")

@app.route("/handledata_vul", methods=['POST'])
def handledata_vul():

        sender_id = request.form['fromses']
        receiver_id = request.form['toses']
        itsm = request.form['itsmfeed']
        itsm_proto = request.form['itsmprotocol']
        itsm_end = request.form['itsmendpoint']
        time = request.form['duration']
        patch_tags = request.form['tags']
        template = request.form['templatename']
        rules = request.form['rulepackages']
        region = request.form['region']
        buck = request.form['bucketname']

        main_apply = "terraform apply -input=false -var='regions=%s' -var='patchgroupinput=%s' -var='inspectorassessmentname=%s' \
                    -var='assessmentduration=%s' -var='rulepackageselection=%s' -var='needitsm=%s' -var='protocolforitsm=%s' \
                    -var='endpointforitsm=%s' -var='sendermailID=%s' -var='receivermailID=%s' \
                    -var='bucketname=%s' -auto-approve -refresh=false -no-color" % (region, patch_tags, template, time, rules, itsm, \
                    itsm_proto, itsm_end, sender_id, receiver_id, buck)
        
        main_apply_shlex = shlex.split(main_apply)
        main_apply_process = subprocess.Popen(main_apply_shlex)
            
        destroy = "terraform destroy"
        destroy_shlex = shlex.split(destroy)
        destroy_process = subprocess.Popen(destroy_shlex)

        return render_template("handledata_vul.html", from_ses=sender_id, to_ses=receiver_id, rules=rules, buck=buck, \
            itsm=itsm, itsmproto=itsm_proto, itsmendpoint=itsm_end, time=time, tags=patch_tags, region=region, templatename= template)


# ----------------------------- CONFIG SECTION ----------------------------

@app.route("/configdesc")
def configdesc():
    return render_template("compliancedesc.html")

@app.route("/configform")
def configform():
    return render_template("complianceform.html")

@app.route("/handledata_compliance", methods = ['POST'])
def handledata_compliance():
    
    region = request.form['region']
    s3avail = request.form['s3avail']
    s3availbuck = request.form['s3availbuck']
    from_ses = request.form['fromses']
    to_ses = request.form['toses']
    report = request.form['report']
    itsm = request.form['itsmfeed']
    itsm_protocol = request.form['itsmprotocol']
    itsm_endpoint = request.form['itsmendpoint']
    buck = request.form['bucketname']

    main_apply = "terraform apply -input=false -var='region=%s' -var='rate=%s' -var='needitsm=%s' -var='protocolforITSM=%s' -var='endpointforITSM=%s' -var='sendermail=%s' -var='receivermail=%s' -var='source_bucket_name=%s' -var='createS3bucket=%s' -var='existingS3bucket=%s' -auto-approve -refresh=false -no-color -lock=false" % (region, report, itsm, itsm_protocol, itsm_endpoint, from_ses, to_ses, buck, s3avail, s3availbuck)
    main_apply_shlex = shlex.split(main_apply)
    main_apply_process = subprocess.Popen(main_apply_shlex)

    destroy = "terraform destroy"
    destroy_shlex = shlex.split(destroy)
    destroy_process = subprocess.Popen(destroy_shlex)

    return render_template("handledata_compliance.html", from_ses=from_ses, to_ses=to_ses, 
        itsm=itsm, itsm_protocol=itsm_protocol, 
        itsm_endpoint=itsm_endpoint,
        region=region, s3avail=s3avail, s3availbuck=s3availbuck, report=report, buck=buck)


# -------------------------------- ASSET SECTION ------------------------------

@app.route("/assetdesc")
def assetdesc():
    return render_template("assetdesc.html")

@app.route("/assetform")
def assetform():
    return render_template("assetform.html")
"""
@app.route("/handledata_asset", methods = ["POST", "GET"])
def handledata_asset():
    return render_template("handledata_asset.html")
"""
if __name__ == "__main__":
    app.run()