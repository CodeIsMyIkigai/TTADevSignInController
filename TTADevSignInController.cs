using ManagementPortal.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Text;
using System.Security.Principal;
/*
    Title: The Tech Academy Developer Sign in Controller
    Author: Chester Terry, student at TTA.

    Description: This controller is intended to be a drop-in tool for developers/students of TTA who are programming
    on MVC 5 applications using individual user auth.  Note: This tool is a serious security issue and should not,
    FOR ANY REASON, be checked into a customer's code base.  Additionally, it should not, AT ANY REASON, be deployed
    to a production environment, or any environment where adhoc user/role creation could cause problems.

    Installation:
    1) Put TTADevSignInController.cs into the controllers director for your appliction.
    2) Right click on the controller in the Solution Explorer and allowing the solution to see the file
    3) Build your project.
    4) Run the application (IIS Express), launching a browser window and go to the following URL: /TTADevSignIn/Index
    
    5) ADD: TTADevSignInController.cs to your ignore file.
 
*/
namespace ManagementPortal.Controllers
{
    [Authorize]
    public class TTADevSignInController : Controller
    {             
       
        [AllowAnonymous]
        public async Task<ActionResult> Index()
        {
            //Get View display data
            
            //Get DB Context to get list of all available roles for the rendered view.
            ApplicationDbContext db = new ApplicationDbContext();
            List<string> allRoles = db.Roles.Select(r => r.Name).ToList<string>();

            //Get UserManager to get appropriate data about the user
            var UserManager = HttpContext.GetOwinContext().Get<ApplicationUserManager>();

            IPrincipal user = HttpContext.User;

            List<string> userRoles;
            string userName;

            if("".Equals(user.Identity.Name))
            {
                //No user logged in.
                userName = "Not currently logged in.";
                userRoles = new List<string>();
            }
            else
            {
                userName = user.Identity.Name;
                string userId = user.Identity.GetUserId();
                userRoles = UserManager.GetRoles(userId).ToList<string>();
            }

            //Render output and return
            string resultHtml = RenderView(userName, userRoles, allRoles, "");
            return base.Content(resultHtml, "text/html", Encoding.UTF8);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> Login(FormCollection formCollection)
        {
            //Get Managers
            var SignInManager = HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            var UserManager = HttpContext.GetOwinContext().Get<ApplicationUserManager>();
            
            //Get DB Context to get list of all available roles for the rendered view.
            ApplicationDbContext db = new ApplicationDbContext();                        
            List<string> allRoles = db.Roles.Select(r => r.Name).ToList<string>();
            
            //Get Command
            string command = formCollection.Get("COMMAND");
            StringBuilder statusMessage = new StringBuilder("One-Click login: <br/><ul>");
            //User Name
            string userName = formCollection.Get("LOGIN_EMAIL");
            string password = formCollection.Get("LOGIN_PASSWORD");

            var result = await SignInManager.PasswordSignInAsync(userName, password, false, shouldLockout: false);
            //If result fails it's because they are not in the database yet.  Create them.
            if (result != SignInStatus.Success)
            {
                statusMessage.Append("<li>Login does not exist. Creating.</li>");
                statusMessage.Append("<li>Email:" + formCollection.Get("LOGIN_EMAIL") + "</li>");
                statusMessage.Append("<li>Pass:" + formCollection.Get("LOGIN_PASSWORD") + "</li>");

                var createUser = new ApplicationUser { UserName = formCollection.Get("LOGIN_EMAIL"), Email = formCollection.Get("LOGIN_EMAIL") };
                var createResult = await UserManager.CreateAsync(createUser, formCollection.Get("LOGIN_PASSWORD"));
                if (createResult.Succeeded)
                {
                    statusMessage.Append("<li>User created.</li>");
                    await SignInManager.SignInAsync(createUser, isPersistent: false, rememberBrowser: false);
                }
                else
                {
                    statusMessage.Append("<li>User creation failed.</li>");
                    statusMessage.Append(createResult.Errors.ToString());
                }
            }
            statusMessage.Append("</ul>");

            ApplicationUser user = UserManager.FindByName(userName);
            List<string> userRoles = UserManager.GetRoles(user.Id).ToList<string>();
            
            string resultHtml = RenderView(userName, userRoles, allRoles, statusMessage.ToString());
            return base.Content(resultHtml, "text/html", Encoding.UTF8);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> CreateUser(FormCollection formCollection)
        {
            //Get Managers
            var SignInManager = HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            var UserManager = HttpContext.GetOwinContext().Get<ApplicationUserManager>();

            //Status Message            
            StringBuilder statusMessage = new StringBuilder("Create login: <br/><ul>");

            //Get DB Context to get list of all available roles for the rendered view.
            ApplicationDbContext db = new ApplicationDbContext();
            List<string> allRoles = db.Roles.Select(r => r.Name).ToList<string>();
            string userName = formCollection.Get("CREATE_EMAIL");
            string password = formCollection.Get("CREATE_PASSWORD");

            string userId;
            List<string> userRoles;
            var user = new ApplicationUser { UserName = userName, Email = userName };
            var regResult = await UserManager.CreateAsync(user, password);
            if (regResult.Succeeded)
            {
                statusMessage.Append("<li>User created.</li>");
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                userId = SignInManager.AuthenticationManager.AuthenticationResponseGrant.Identity.GetUserId();
                userRoles = UserManager.GetRoles(userId).ToList<string>();
            }
            else
            {   
                statusMessage.Append("<li>User creation failed:<ul>");
                foreach(string error in regResult.Errors)
                {
                    statusMessage.Append("<li>" + error + "</li>");
                }
                statusMessage.Append("</ul></li>");
                //No user logged in.
                userName = "Not currently logged in.";
                userRoles = new List<string>();
            }

            string resultHtml = RenderView(userName, userRoles, allRoles, statusMessage.ToString());
            return base.Content(resultHtml, "text/html", Encoding.UTF8);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> AssignRoles(FormCollection formCollection)
        {
            //Get Managers
            var SignInManager = HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            var UserManager = HttpContext.GetOwinContext().Get<ApplicationUserManager>();

            //Get DB Context to get list of all available roles for the rendered view.
            ApplicationDbContext db = new ApplicationDbContext();
            string[] allRoles = db.Roles.Select(r => r.Name).ToArray<string>();

            StringBuilder statusMessage = new StringBuilder("<ul>");

            string roleString = formCollection.Get("ASSIGNED_ROLES");
            string[] roles = roleString.Split(',');

            statusMessage.Append("<li>Assigned Roles:" + roleString + "</li>");

            UserManager = HttpContext.GetOwinContext().Get<ApplicationUserManager>();

            string userId = HttpContext.User.Identity.GetUserId();

            string userName = null;
            List<string> userRoles = null;

            if (userId != null && "" != userId)
            {
                statusMessage.Append("<li>UserId: " + userId + "</li>");
                string[] currentRoles = UserManager.GetRoles(userId).ToArray<string>();
                UserManager.RemoveFromRoles(userId, currentRoles);

                IdentityResult irResult = UserManager.AddToRoles(userId, roles);

                if (irResult.Succeeded)
                {
                    statusMessage.Append("<li>Role Assignment:  succeeded.</li>");
                }
                else
                {
                    statusMessage.Append("<li>Role Assignment failed:<ul>");
                    foreach (string error in irResult.Errors)
                    {
                        statusMessage.Append("<li>" + error + "</li>");
                    }
                    statusMessage.Append("</ul></li>");
                }

                ApplicationUser user = UserManager.FindById(userId);
                userName = user.UserName;
                userRoles = UserManager.GetRoles(user.Id).ToList<string>();
            }
            else
            {
                userName = "Not currently logged in.";
                userRoles = new List<string>();
                statusMessage.Append("<li>No user logged in and unable to assign role.</li>");
            }

            string resultHtml = RenderView(userName, userRoles, allRoles.ToList<string>(), statusMessage.ToString());
            return base.Content(resultHtml, "text/html", Encoding.UTF8);
        }

        [AllowAnonymous]
        public async Task<ActionResult> CreateRole(FormCollection formCollection)
        {
            //Status for output.
            StringBuilder statusMessage = new StringBuilder("Role Creation: <ul>");

            //Get DB Context to get list of all available roles for the rendered view and to create new role
            ApplicationDbContext db = new ApplicationDbContext();

            //The new role name subbmited by the user
            string newRole = formCollection.Get("CREATE_ROLE");
            statusMessage.Append("<li>New Role: " + newRole + "</li>");

            //Create the role
            try
            {
                //Instanciate role manager to create the role.
                var RoleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
                //Check to see if the role exists and create it if it does not already exist.
                if (!RoleManager.RoleExists(newRole))
                {
                    var role = new Microsoft.AspNet.Identity.EntityFramework.IdentityRole
                    {
                        Name = newRole
                    };
                    RoleManager.Create(role);
                }
                statusMessage.Append("<li>Result: Role created successfully.</li>");
            }
            catch(Exception e)
            {
                statusMessage.Append("<li>Result: Error creating role:<ul><li>" + e.ToString() + "</li></ul></li>");
            }

            //Setup output
            List<string> userRoles;
            string userName;
            //This user may or may not be logged in, so check and get the appropriate data for the rendered view
            IPrincipal user = HttpContext.User;  

            if ("".Equals(user.Identity.Name))  //User is not logged in
            {
                //No user logged in.
                userName = "Not currently logged in.";
                userRoles = new List<string>();
            }
            else  //User is logged in
            {
                userName = user.Identity.Name;
                string userId = user.Identity.GetUserId();
                //Get UserManager to get appropriate roles
                var UserManager = HttpContext.GetOwinContext().Get<ApplicationUserManager>();
                userRoles = UserManager.GetRoles(userId).ToList<string>();
            }

            //Getting all roles for rendered output.  (After the creation)
            List<string> allRoles = db.Roles.Select(r => r.Name).ToList<string>();

            //Render output and return
            string resultHtml = RenderView(userName, userRoles, allRoles, statusMessage.ToString());
            return base.Content(resultHtml, "text/html", Encoding.UTF8);
        }
        
        public string RenderView(string userName, List<string> userRoles, List<string> allRoles, string statusMessage)
        {            
            StringBuilder sbOutput = new StringBuilder();

            //Sort Role Lists
            allRoles.Sort();
            userRoles.Sort();

            sbOutput.Append("<!DOCTYPE html>");
            sbOutput.Append("<html lang=\"en\">");
            sbOutput.Append("<head>");
            sbOutput.Append("  <title>Bootstrap Example</title>");
            sbOutput.Append("  <meta charset=\"utf-8\">");
            sbOutput.Append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");

            //Bootstrap and jQuery
            sbOutput.Append("<link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css\" integrity=\"sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T\" crossorigin=\"anonymous\">");
            sbOutput.Append("<script src=\"https://code.jquery.com/jquery-3.3.1.slim.min.js\" integrity=\"sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo\" crossorigin=\"anonymous\"></script>");
            sbOutput.Append("<script src=\"https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js\" integrity=\"sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1\" crossorigin=\"anonymous\"></script>");
            sbOutput.Append("<script src=\"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js\" integrity=\"sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM\" crossorigin=\"anonymous\"></script>");


            //Script Section for one-click login.
            sbOutput.Append("<script type=\"text/javascript\">\n");
            
            sbOutput.Append("console.log(\"HERE\");\n");
            sbOutput.Append("   var userData = new Object();\n");
            sbOutput.Append("       userData['Jack'] = { Password: '!Pass1234', Email: 'test@gmail.com' };\n");
            sbOutput.Append("       userData['Jill'] = { Password: '123ABCdef!', Email: 'hello@gmail.com' };\n");
            sbOutput.Append("       userData['Joe'] = { Password: ' 789asdASD!', Email: 'joe@doe.com' };\n");
            sbOutput.Append("   function setFormData(form, userName)\n");
            sbOutput.Append("   {\n");     
            sbOutput.Append("        form.elements[\"LOGIN_EMAIL\"].value = userData[userName].Email;\n");            
            sbOutput.Append("        form.elements[\"LOGIN_PASSWORD\"].value = userData[userName].Password;\n");            
            sbOutput.Append("        form.submit();\n");
            sbOutput.Append("   }\n");            
            sbOutput.Append("</script>\n");
            sbOutput.Append("</head>");

            sbOutput.Append("<body>");
            sbOutput.Append("<div class=\"container\">");
            sbOutput.Append("  <h2 class=\"mt-5\">The Tech Academy Development Sign In App</h2>");
            sbOutput.Append("  <p>The purpose of this tool is to allow TTA Developers to sign into and application without hassle.<br /><b> This Controller and it's Views should never be deployed to a customer site.</b></p>");
            if(userName != null && userName != "")
            {
                sbOutput.Append("<div class=\"card mb-3\" style=\"width: 18rem;\">");
                sbOutput.Append("  <div class=\"card-body\">");
                sbOutput.Append("    <h5 class=\"card-title\">Logged In</h5>");
                sbOutput.Append("    <p class=\"card-text\">");
                sbOutput.Append(userName);                
                sbOutput.Append("    </p>");
                sbOutput.Append("  </div>");
                sbOutput.Append("</div>\n");
            }
            if(statusMessage != "")
            {
                sbOutput.Append("<div class=\"card mb-3\" style=\"width: 18rem;\">");
                sbOutput.Append("  <div class=\"card-body\">");
                sbOutput.Append("    <h5 class=\"card-title\">Status Message</h5>");
                sbOutput.Append("    <p class=\"card-text\">");
                sbOutput.Append(statusMessage);
                sbOutput.Append("    </p>");
                sbOutput.Append("  </div>");
                sbOutput.Append("</div>\n");
            }

            sbOutput.Append("  <ul class=\"nav nav-pills\">");
            sbOutput.Append("    <li class=\"nav-item\">");
            sbOutput.Append("       <a class=\"nav-link active\" data-toggle=\"pill\" href=\"#home\">Logins</a>");
            sbOutput.Append("    </li>");
            sbOutput.Append("    <li class=\"nav-item\">");
            sbOutput.Append("       <a class=\"nav-link\" data-toggle=\"pill\" href=\"#menu1\">Create Login</a>");
            sbOutput.Append("    </li>");
            sbOutput.Append("    <li class=\"nav-item\">");
            sbOutput.Append("       <a class=\"nav-link\" data-toggle=\"pill\" href=\"#menu2\">Assign Roles</a>");
            sbOutput.Append("    </li>");
            sbOutput.Append("    <li class=\"nav-item\">");
            sbOutput.Append("       <a class=\"nav-link\" data-toggle=\"pill\" href=\"#menu3\">Create Role</a>");
            sbOutput.Append("    </li>");
            sbOutput.Append("  </ul><div>&nbsp;</div>");
            sbOutput.Append("  <div class=\"tab-content\">");
            sbOutput.Append("    <div id=\"home\" class=\"tab-pane container active\">");
            sbOutput.Append("        <h3>Logins</h3>");
            sbOutput.Append("        <p>");
            sbOutput.Append("        <form name=\"CREATE_LOGIN_FORM\" action=\"/TTADevSignIn/Login\" method=\"POST\" method=\"POST\" class=\"form-group\" />");
            sbOutput.Append("           <input type=\"hidden\" name=\"COMMAND\" value=\"ONE_CLICK_LOGIN\" />");
            sbOutput.Append("           <div class=\"form-group\">");
            sbOutput.Append("                <span class=\"col-md-2\"><button type=\"button\" class=\"btn btn-primary\" onclick=\"setFormData(this.form, 'Jack');\"> Jack </button></span>");
            sbOutput.Append("                <span class=\"col-md-3\">test@gmail.com</span");
            sbOutput.Append("                <span class=\"col-md-2\">Admin</span>");
            sbOutput.Append("            </div>");
            sbOutput.Append("            <div class=\"form-group\">");
            sbOutput.Append("                <span class=\"col-md-2\"><button type=\"button\" class=\"btn btn-primary\" onclick=\"setFormData(this.form, 'Jill');\"> Jill </button></span>");
            sbOutput.Append("                <span class=\"col-md-3\">test@123.com</span>");
            sbOutput.Append("                <span class=\"col-md-2\">Manager</span>");
            sbOutput.Append("           </div>");
            sbOutput.Append("            <div class=\"form-group\">");
            sbOutput.Append("                <span class=\"col-md-2\"><button type=\"button\" class=\"btn btn-primary\" onclick=\"setFormData(this.form, 'Joe');\"> Joe </button></span>");
            sbOutput.Append("                <span class=\"col-md-3\">joe @doe.com</span>");
            sbOutput.Append("                <span class=\"col-md-2\">Employee</span>");
            sbOutput.Append("            </div>");
            sbOutput.Append("            <input type=\"hidden\" name=\"LOGIN_EMAIL\" value=\"\" />");
            sbOutput.Append("            <input type=\"hidden\" name=\"LOGIN_PASSWORD\" value=\"\" />");
            sbOutput.Append("        </form>");                                                  
            sbOutput.Append("        </p>");
            sbOutput.Append("    </div>");

            sbOutput.Append("    <div id=\"menu1\" class=\"tab-pane container fade\">");
            sbOutput.Append("        <h3>Create Login</h3>");
            sbOutput.Append("        <p>");
            sbOutput.Append("        <form name=\"CREATE_USER_FORM\" action=\"/TTADevSignIn/CreateUser\" method=\"POST\" class=\"form-group\" />");
            sbOutput.Append("            <input type=\"hidden\" name=\"COMMAND\" value=\"CREATE_USER\" />");
            sbOutput.Append("            <div class=\"form-group\">");
            sbOutput.Append("                <label for=\"exampleInputEmail1\">Email address/Login Name</label>");
            sbOutput.Append("                <input type=\"email\" class=\"form-control\" id=\"exampleInputEmail1\" aria-describedby=\"emailHelp\" name=\"CREATE_EMAIL\" placeholder=\"Enter email\">");           
            sbOutput.Append("            </div>");
            sbOutput.Append("            <div class=\"form-group\">");
            sbOutput.Append("                <label for=\"exampleInputPassword1\">Password</label>");
            sbOutput.Append("                <input type=\"password\" class=\"form-control\" id=\"exampleInputPassword1\" name=\"CREATE_PASSWORD\" placeholder=\"Passwords must be at least 6 characters, at least one non letter or digit, at least one digit ('0'-'9'), at least one uppercase ('A'-'Z').\">");
            sbOutput.Append("            </div>");
            sbOutput.Append("            <button type=\"submit\" class=\"btn btn-primary\">Submit</button>");
            sbOutput.Append("        </form");
            sbOutput.Append("        </p>");
            sbOutput.Append("    </div>");


            sbOutput.Append("    <div id=\"menu2\" class=\"tab-pane container fade\">");
            sbOutput.Append("        <h3>Assign Roles</h3>");
            sbOutput.Append("        <p>");
            sbOutput.Append("        <form name=\"ASSIGN_ROLES_FORM\" action=\"/TTADevSignIn/AssignRoles\" method=\"POST\" class=\"form-group\" />");
            sbOutput.Append("            <input type=\"hidden\" name=\"COMMAND\" value=\"ASSIGN_ROLES\" />");            
            sbOutput.Append("            <div class=\"form-group\">");
            sbOutput.Append("                <label for=\"ASSIGNED_ROLES\"><b>Roles:</b> Use CTRL-Click to select single or multiple roles.</label>\n");
            sbOutput.Append("                <select multiple class=\"form-control\" name=\"ASSIGNED_ROLES\">\n");            
            
            foreach (string role in allRoles)
            {
                sbOutput.Append("                    <option value=\"");
                sbOutput.Append(role);
                sbOutput.Append("\"");
                if (userRoles.Contains(role))
                {
                    sbOutput.Append(" selected=\"TRUE\" ");                    
                }                    
                sbOutput.Append(">");
                sbOutput.Append(role);
                sbOutput.Append("</option>\n");
            }
            sbOutput.Append("                </select>\n");
            sbOutput.Append("            </div>");
            sbOutput.Append("            <button type=\"submit\" class=\"btn btn-primary\">Submit</button>");
            sbOutput.Append("        </form");

            sbOutput.Append("        </p>");
            sbOutput.Append("    </div>");

            sbOutput.Append("    <div id=\"menu3\" class=\"tab-pane container fade\">");
            sbOutput.Append("        <h3>Create Role</h3>");
            sbOutput.Append("        <p>");
            //list Roles
            sbOutput.Append("        <ul>");
            foreach (string role in allRoles)
            {
                sbOutput.Append("            <li>");
                sbOutput.Append(role);
                sbOutput.Append("</li>");
            }
            sbOutput.Append("        </ul>");
            //Roles Form
            sbOutput.Append("        <form name=\"CREATE_ROLE_FORM\" action=\"/TTADevSignIn/CreateRole\" method=\"POST\" class=\"form-group\" />");
            sbOutput.Append("            <input type=\"hidden\" name=\"COMMAND\" value\"CREATE_ROLE\" />");
            sbOutput.Append("            <div class=\"form-group\">");
            sbOutput.Append("                <label for=\"new_role_1\">New Role Name</label>");
            sbOutput.Append("                <input type=\"text\" class=\"form-control\" id=\"new_role_1\" name=\"CREATE_ROLE\" placeholder=\"Enter Role Name\">");
            sbOutput.Append("            </div>");            
            sbOutput.Append("            <button type=\"submit\" class=\"btn btn-primary\">Submit</button>");
            sbOutput.Append("        </form");
            sbOutput.Append("        </p>");
            sbOutput.Append("    </div>");
            sbOutput.Append("  </div>");
            sbOutput.Append("</div>");
            sbOutput.Append("</body>");
            sbOutput.Append("</html>");

            return sbOutput.ToString();
        }
    }     
}